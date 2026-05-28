"""WebSocket stream support for Cobalt Strike beacon console output."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote, urlparse, urlunparse

try:
    import websocket
except ImportError:  # pragma: no cover - exercised only when dependency is absent
    websocket = None

from fastmcp import FastMCP

from cs_audit import audit_event
from cs_client import CobaltStrikeClient

logger = logging.getLogger(__name__)

BEACONS_DESTINATION = "/subscribe/beacons"
EVENTLOG_DESTINATION = "/subscribe/eventlog"
BEACONLOG_DESTINATION_TEMPLATE = "/subscribe/beaconlog/{bid}"
TASK_IN_PROGRESS_STATUSES = {"QUEUED", "PENDING", "RUNNING", "IN_PROGRESS", "IN PROGRESS"}
TASK_TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELED", "CANCELLED", "TIMEOUT", "TIMED_OUT"}
DEFAULT_SLEEP_WAIT_MARGIN_SECONDS = 30.0
DEFAULT_SLEEP_WAIT_CYCLES = 2.0
LONG_SLEEP_NOTICE_THRESHOLD_SECONDS = 60.0
STREAM_READY_WAIT_SECONDS = 3.0
MAX_STREAM_BUFFER_SIZE = 10_000
BEACON_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def build_connect_frame(token: str, host: str) -> str:
    return f"CONNECT\nAuthorization:Bearer {token}\naccept-version:1.2\nhost:{host}\n\n\x00"


def build_subscribe_frame(destination: str, frame_id: int = 1, ack: str = "auto") -> str:
    return f"SUBSCRIBE\nid:{frame_id}\ndestination:{destination}\nack:{ack}\n\n\x00"


def validate_beacon_id(bid: str) -> str:
    """Validate and normalize beacon IDs before using them in paths or STOMP frames."""
    normalized = str(bid).strip()
    if not normalized:
        raise ValueError("bid cannot be empty")
    if not BEACON_ID_RE.fullmatch(normalized):
        raise ValueError("bid contains invalid characters")
    return normalized


def _encoded_beacon_id(bid: str) -> str:
    return quote(validate_beacon_id(bid), safe="")


def _beaconlog_destination(bid: str) -> str:
    return BEACONLOG_DESTINATION_TEMPLATE.format(bid=_encoded_beacon_id(bid))


def parse_stomp_frame(raw_message: str) -> dict[str, Any]:
    header_section, _, body = raw_message.partition("\n\n")
    body = body.rstrip("\x00")

    lines = header_section.split("\n")
    command = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    parsed_body: Any = None
    if body:
        try:
            parsed_body = json.loads(body)
        except json.JSONDecodeError:
            parsed_body = body

    return {"command": command, "headers": headers, "body": parsed_body}


def _websocket_url_from_base_url(base_url: str) -> tuple[str, str]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Unsupported Cobalt Strike API base URL: {base_url}")

    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_url = urlunparse((ws_scheme, parsed.netloc, "/connect", "", "", ""))
    return ws_url, parsed.hostname or parsed.netloc


def _extract_rendered_output(body: Any) -> list[str]:
    if isinstance(body, dict):
        value = body.get("renderedOutput") or body.get("rendered_output") or body.get("text")
        if value:
            return [str(value)]
        return []
    if isinstance(body, str) and body:
        return [body]
    return []


@dataclass(frozen=True)
class StreamEntry:
    sequence: int
    timestamp: float
    data: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "data": self.data,
        }


class StreamBuffer:
    def __init__(self, maxlen: int):
        self._entries: deque[StreamEntry] = deque(maxlen=maxlen)
        self._condition = threading.Condition()
        self._sequence = 0

    @property
    def sequence(self) -> int:
        with self._condition:
            return self._sequence

    @property
    def first_sequence(self) -> int | None:
        with self._condition:
            return self._entries[0].sequence if self._entries else None

    def append(self, data: Any) -> int:
        with self._condition:
            self._sequence += 1
            entry = StreamEntry(self._sequence, time.time(), data)
            self._entries.append(entry)
            self._condition.notify_all()
            return entry.sequence

    def tail(self, count: int) -> list[dict[str, Any]]:
        count = max(1, min(count, self._entries.maxlen or count))
        with self._condition:
            return [entry.to_dict() for entry in list(self._entries)[-count:]]

    def since(self, sequence: int) -> list[StreamEntry]:
        with self._condition:
            return [entry for entry in self._entries if entry.sequence > sequence]

    def wait_for_entries(
        self,
        after_sequence: int,
        timeout_seconds: float,
        poll_seconds: float = 0.25,
    ) -> list[StreamEntry]:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        with self._condition:
            while True:
                entries = [entry for entry in self._entries if entry.sequence > after_sequence]
                if entries:
                    return entries
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._condition.wait(min(remaining, poll_seconds))

    def wait_for_quiet(
        self,
        after_sequence: int,
        timeout_seconds: float,
        quiet_seconds: float,
    ) -> list[dict[str, Any]]:
        return self.wait_for_quiet_result(
            after_sequence,
            timeout_seconds,
            quiet_seconds,
        )["entries"]

    def wait_for_quiet_result(
        self,
        after_sequence: int,
        timeout_seconds: float,
        quiet_seconds: float,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        quiet_seconds = max(0.0, quiet_seconds)
        last_sequence = -1
        last_change = time.monotonic()

        with self._condition:
            while True:
                entries = [entry for entry in self._entries if entry.sequence > after_sequence]
                now = time.monotonic()
                current_sequence = entries[-1].sequence if entries else self._sequence

                if current_sequence != last_sequence:
                    last_sequence = current_sequence
                    last_change = now

                if entries and now - last_change >= quiet_seconds:
                    return self._result_after_locked(after_sequence)

                remaining = deadline - now
                if remaining <= 0:
                    return self._result_after_locked(after_sequence)

                wait_for = min(remaining, quiet_seconds or remaining, 0.25)
                self._condition.wait(wait_for)

    def result_since(self, after_sequence: int) -> dict[str, Any]:
        with self._condition:
            return self._result_after_locked(after_sequence)

    def _result_after_locked(self, after_sequence: int) -> dict[str, Any]:
        entries = [entry for entry in self._entries if entry.sequence > after_sequence]
        first_retained = self._entries[0].sequence if self._entries else None
        dropped_entries = 0
        if first_retained is not None and after_sequence < first_retained - 1:
            dropped_entries = first_retained - after_sequence - 1

        return {
            "entries": [entry.to_dict() for entry in entries],
            "after_sequence": after_sequence,
            "first_retained_sequence": first_retained,
            "last_sequence": self._sequence,
            "truncated": dropped_entries > 0,
            "dropped_entries": dropped_entries,
        }


class CobaltStrikeWebSocketStream:
    def __init__(
        self,
        *,
        ws_url: str,
        host: str,
        token_provider: Callable[[], str],
        token_refresh: Callable[[], bool] | None = None,
        destination: str,
        verify_tls: bool,
        reconnect_seconds: float,
        on_payload,
    ):
        self.ws_url = ws_url
        self.host = host
        self.token_provider = token_provider
        self.token_refresh = token_refresh
        self.destination = destination
        self.verify_tls = verify_tls
        self.reconnect_seconds = reconnect_seconds
        self.on_payload = on_payload
        self.status = "initialized"
        self.last_error = ""
        self._state_lock = threading.Lock()
        self._ready_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._ws = None

    def start(self) -> None:
        if websocket is None:
            self._set_status("dependency_missing", "Missing dependency: websocket-client")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._ready_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"cs-ws-{self.destination}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, join_timeout: float = 2.0) -> None:
        self._stop_event.set()
        self._ready_event.clear()
        with self._state_lock:
            ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=join_timeout)

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def wait_until_ready(self, timeout_seconds: float) -> bool:
        return self._ready_event.wait(max(0.0, timeout_seconds))

    def to_status(self) -> dict[str, Any]:
        with self._state_lock:
            status = self.status
            last_error = self.last_error
        return {
            "destination": self.destination,
            "status": status,
            "last_error": last_error,
            "alive": self.is_alive(),
            "ready": self._ready_event.is_set(),
        }

    def _on_message(self, _ws, message: str) -> None:
        frame = parse_stomp_frame(message)
        command = frame.get("command")
        if command == "ERROR":
            self._ready_event.clear()
            self._set_status("error", self._format_error(frame))
            if self._is_auth_error(frame) and self._refresh_token():
                try:
                    _ws.close()
                except Exception:
                    pass
            return
        if command == "CONNECTED":
            self._set_status("connected")
            self._send_subscribe(_ws)
            return
        body = frame.get("body")
        if body is not None:
            self.on_payload(body)

    def _on_error(self, _ws, error: Any) -> None:
        self._ready_event.clear()
        self._set_status("error", str(error))

    def _on_close(self, _ws, _close_status_code, _close_msg) -> None:
        self._ready_event.clear()
        if not self._stop_event.is_set():
            self._set_status("disconnected")

    def _on_open(self, ws) -> None:
        self._set_status("connected")
        ws.send(build_connect_frame(self.token_provider(), self.host))

    def _run_loop(self) -> None:
        reconnecting = False
        while not self._stop_event.is_set():
            try:
                self._ready_event.clear()
                self._set_status("connecting")
                if reconnecting:
                    self._refresh_token()
                token = self.token_provider()
                ws_app = websocket.WebSocketApp(
                    self.ws_url,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open,
                    header=[f"Authorization: Bearer {token}"],
                )
                with self._state_lock:
                    self._ws = ws_app
                ws_app.run_forever(
                    sslopt={
                        "cert_reqs": ssl.CERT_REQUIRED if self.verify_tls else ssl.CERT_NONE,
                    }
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._ready_event.clear()
                self._set_status("error", str(exc))
            finally:
                with self._state_lock:
                    self._ws = None

            if not self._stop_event.is_set():
                reconnecting = True
                self._stop_event.wait(max(0.1, self.reconnect_seconds))

        self._ready_event.clear()
        self._set_status("stopped")

    def _send_subscribe(self, ws) -> None:
        try:
            ws.send(build_subscribe_frame(self.destination))
            self._ready_event.set()
        except Exception as exc:  # pylint: disable=broad-except
            self._ready_event.clear()
            self._set_status("error", str(exc))

    def _set_status(self, status: str, last_error: str | None = None) -> None:
        with self._state_lock:
            self.status = status
            if last_error is not None:
                self.last_error = last_error

    def _refresh_token(self) -> bool:
        if self.token_refresh is None:
            return False
        try:
            return bool(self.token_refresh())
        except Exception as exc:  # pylint: disable=broad-except
            self._set_status("error", f"token refresh failed: {exc}")
            return False

    @staticmethod
    def _format_error(frame: dict[str, Any]) -> str:
        body = frame.get("body")
        if isinstance(body, dict):
            return body.get("message") or body.get("error") or json.dumps(body)
        return str(body) if body else "stream error"

    @classmethod
    def _is_auth_error(cls, frame: dict[str, Any]) -> bool:
        rendered = cls._format_error(frame).lower()
        return any(marker in rendered for marker in ("401", "403", "auth", "token", "unauthorized", "forbidden"))


class CobaltStrikeWebSocketStreamManager:
    def __init__(
        self,
        cs_client: CobaltStrikeClient,
        *,
        enabled: bool = True,
        auto_start: bool = False,
        buffer_size: int = 1000,
        reconnect_seconds: float = 2.0,
    ):
        self.cs_client = cs_client
        self.enabled = enabled
        self.auto_start = auto_start
        self.buffer_size = max(100, min(buffer_size, MAX_STREAM_BUFFER_SIZE))
        self.reconnect_seconds = reconnect_seconds
        self._lock = threading.Lock()
        self._eventlog = StreamBuffer(self.buffer_size)
        self._beacon_logs: dict[str, StreamBuffer] = {}
        self._beacons_payload: Any = None
        self._beacons_updated_at: float | None = None
        self._streams: dict[str, CobaltStrikeWebSocketStream] = {}

    def start_defaults(self) -> None:
        if not self.enabled:
            return
        self.ensure_eventlog_stream()
        self.ensure_beacons_stream()

    def stop_all(self) -> None:
        with self._lock:
            streams = list(self._streams.values())
        for stream in streams:
            stream.stop()
        with self._lock:
            self._streams.clear()

    def ensure_eventlog_stream(self) -> None:
        if not self.enabled:
            return
        self._ensure_stream(
            EVENTLOG_DESTINATION,
            lambda body: [self._eventlog.append(line) for line in _extract_rendered_output(body)],
        )

    def ensure_beacons_stream(self) -> None:
        if not self.enabled:
            return
        def on_beacons(body: Any) -> None:
            with self._lock:
                self._beacons_payload = body
                self._beacons_updated_at = time.time()

        self._ensure_stream(BEACONS_DESTINATION, on_beacons)

    def ensure_beaconlog_stream(self, bid: str) -> CobaltStrikeWebSocketStream | None:
        if not self.enabled:
            return None
        normalized_bid = validate_beacon_id(bid)
        destination = _beaconlog_destination(normalized_bid)
        buffer = self._beacon_buffer(normalized_bid)
        return self._ensure_stream(
            destination,
            lambda body: [buffer.append(line) for line in _extract_rendered_output(body)],
        )

    def eventlog_tail(self, lines: int) -> dict[str, Any]:
        if not self._streams_available():
            return self._unavailable_result(EVENTLOG_DESTINATION)
        self.ensure_eventlog_stream()
        return {
            "stream": EVENTLOG_DESTINATION,
            "entries": self._eventlog.tail(lines),
        }

    def beaconlog_tail(self, bid: str, lines: int) -> dict[str, Any]:
        try:
            normalized_bid = validate_beacon_id(bid)
        except ValueError as exc:
            return {
                "bid": str(bid),
                "error": str(exc),
                "entries": [],
            }
        if not self._streams_available():
            return self._unavailable_result(_beaconlog_destination(normalized_bid))
        self.ensure_beaconlog_stream(normalized_bid)
        return {
            "stream": _beaconlog_destination(normalized_bid),
            "entries": self._beacon_buffer(normalized_bid).tail(lines),
        }

    def beacons_snapshot(self) -> dict[str, Any]:
        if not self._streams_available():
            return self._unavailable_result(BEACONS_DESTINATION)
        self.ensure_beacons_stream()
        with self._lock:
            return {
                "stream": BEACONS_DESTINATION,
                "updated_at": self._beacons_updated_at,
                "payload": self._beacons_payload,
            }

    async def execute_console_and_wait(
        self,
        bid: str,
        command_line: str,
        timeout_seconds: float,
        quiet_seconds: float,
    ) -> dict[str, Any]:
        try:
            normalized_bid = validate_beacon_id(bid)
        except ValueError as exc:
            return {
                "error": str(exc),
                "bid": str(bid),
                "command_line": command_line,
                "task_submitted": False,
            }
        if not command_line.strip():
            return {"error": "command_line cannot be empty"}

        audit_event(
            "tool_invocation",
            tool_name="executeBeaconConsoleAndWait",
            beacon_id=normalized_bid,
            status="started",
        )

        if not self._streams_available():
            return await self._execute_console_and_wait_rest_only(
                bid=normalized_bid,
                command_line=command_line,
                timeout_seconds=timeout_seconds,
            )

        stream = self.ensure_beaconlog_stream(normalized_bid)
        stream_ready = False
        if stream is not None:
            stream_ready = await asyncio.to_thread(
                stream.wait_until_ready,
                min(STREAM_READY_WAIT_SECONDS, max(0.1, timeout_seconds)),
            )
        buffer = self._beacon_buffer(normalized_bid)
        cursor = buffer.sequence
        wait_profile = await self._build_wait_profile(normalized_bid, timeout_seconds)
        effective_timeout_seconds = wait_profile["effective_timeout_seconds"]

        task_result = await self._execute_console_command(normalized_bid, command_line)
        if isinstance(task_result, dict) and task_result.get("error"):
            audit_event(
                "tool_invocation",
                tool_name="executeBeaconConsoleAndWait",
                beacon_id=normalized_bid,
                task_id=_task_id(task_result),
                status="failed",
                details={"output_source": "websocket"},
            )
            return {
                "bid": normalized_bid,
                "command_line": command_line,
                "task": task_result,
                "task_id": _task_id(task_result),
                "task_status_path": _task_status_path(task_result),
                "wait_profile": wait_profile,
                "stream_ready_before_submit": stream_ready,
                "output": [],
                "output_source": "websocket",
                "output_correlation": "best_effort",
                "timed_out": False,
                "task_completed": False,
                "output_complete": False,
            }

        task_detail = await self._wait_for_task_terminal(
            task_result=task_result,
            timeout_seconds=effective_timeout_seconds,
        )
        task_completed = _task_is_terminal(task_detail.get("task"))
        remaining = max(0.1, task_detail.get("remaining_seconds", 0.1))

        # The REST task can become terminal slightly before the final console
        # frame reaches the websocket subscriber. Drain briefly after completion.
        output_result = await asyncio.to_thread(
            buffer.wait_for_quiet_result,
            cursor,
            min(max(quiet_seconds, 0.1) + 1.0, remaining if not task_completed else max(quiet_seconds, 0.1) + 1.0),
            quiet_seconds,
        )
        result = {
            "bid": normalized_bid,
            "command_line": command_line,
            "task": task_result,
            "task_id": _task_id(task_result),
            "task_status_path": _task_status_path(task_result),
            "task_detail": task_detail.get("task"),
            "wait_profile": wait_profile,
            "stream_ready_before_submit": stream_ready,
            "output": output_result["entries"],
            "output_source": "websocket",
            "output_correlation": "best_effort",
            "output_buffer": {
                "after_sequence": output_result["after_sequence"],
                "first_retained_sequence": output_result["first_retained_sequence"],
                "last_sequence": output_result["last_sequence"],
                "truncated": output_result["truncated"],
                "dropped_entries": output_result["dropped_entries"],
            },
            "timed_out": task_detail.get("timed_out", False),
            "task_completed": task_completed,
            "output_complete": task_completed and not task_detail.get("timed_out", False),
        }
        audit_event(
            "tool_invocation",
            tool_name="executeBeaconConsoleAndWait",
            beacon_id=normalized_bid,
            task_id=result.get("task_id"),
            status="completed" if task_completed else "timed_out",
            details={
                "output_source": result.get("output_source"),
                "output_complete": result.get("output_complete"),
            },
        )
        return result

    async def _execute_console_and_wait_rest_only(
        self,
        *,
        bid: str,
        command_line: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        wait_profile = await self._build_wait_profile(bid, timeout_seconds)
        effective_timeout_seconds = wait_profile["effective_timeout_seconds"]

        task_result = await self._execute_console_command(bid, command_line)
        if isinstance(task_result, dict) and task_result.get("error"):
            audit_event(
                "tool_invocation",
                tool_name="executeBeaconConsoleAndWait",
                beacon_id=bid,
                task_id=_task_id(task_result),
                status="failed",
                details={"output_source": "rest_task_poll"},
            )
            return {
                "bid": bid,
                "command_line": command_line,
                "task": task_result,
                "task_id": _task_id(task_result),
                "task_status_path": _task_status_path(task_result),
                "wait_profile": wait_profile,
                "task_submitted": False,
                "output": [],
                "output_source": "rest_task_poll",
                "output_correlation": "unavailable",
                "output_complete": False,
                "output_unavailable_reason": self._unavailable_message(),
                "timed_out": False,
                "task_completed": False,
            }

        task_detail = await self._wait_for_task_terminal(
            task_result=task_result,
            timeout_seconds=effective_timeout_seconds,
        )
        task_completed = _task_is_terminal(task_detail.get("task"))
        result = {
            "bid": bid,
            "command_line": command_line,
            "task": task_result,
            "task_id": _task_id(task_result),
            "task_status_path": _task_status_path(task_result),
            "task_detail": task_detail.get("task"),
            "wait_profile": wait_profile,
            "task_submitted": True,
            "output": [],
            "output_source": "rest_task_poll",
            "output_correlation": "unavailable",
            "output_complete": False,
            "output_unavailable_reason": self._unavailable_message(),
            "timed_out": task_detail.get("timed_out", False),
            "task_completed": task_completed,
        }
        audit_event(
            "tool_invocation",
            tool_name="executeBeaconConsoleAndWait",
            beacon_id=bid,
            task_id=result.get("task_id"),
            status="completed" if task_completed else "timed_out",
            details={"output_source": result.get("output_source")},
        )
        return result

    def status(self) -> dict[str, Any]:
        with self._lock:
            streams = {name: stream.to_status() for name, stream in self._streams.items()}
            beacon_buffers = {
                bid: {"sequence": buffer.sequence, "entries": len(buffer.tail(self.buffer_size))}
                for bid, buffer in self._beacon_logs.items()
            }
        return {
            "enabled": self.enabled,
            "dependency_available": websocket is not None,
            "base_url": self.cs_client.base_url,
            "streams": streams,
            "buffers": {
                "eventlog_sequence": self._eventlog.sequence,
                "beacon_logs": beacon_buffers,
            },
        }

    def _ensure_stream(self, destination: str, on_payload) -> CobaltStrikeWebSocketStream | None:
        if not self._streams_available():
            return None
        with self._lock:
            existing = self._streams.get(destination)
            if existing and existing.is_alive():
                existing.start()
                return existing
            if existing:
                self._streams.pop(destination, None)

            ws_url, host = _websocket_url_from_base_url(self.cs_client.base_url)
            stream = CobaltStrikeWebSocketStream(
                ws_url=ws_url,
                host=host,
                token_provider=lambda: self.cs_client.access_token,
                token_refresh=self.cs_client.reauthenticate_blocking,
                destination=destination,
                verify_tls=self.cs_client.verify_tls,
                reconnect_seconds=self.reconnect_seconds,
                on_payload=on_payload,
            )
            self._streams[destination] = stream
            stream.start()
            return stream

    def _beacon_buffer(self, bid: str) -> StreamBuffer:
        with self._lock:
            buffer = self._beacon_logs.get(bid)
            if buffer is None:
                buffer = StreamBuffer(self.buffer_size)
                self._beacon_logs[bid] = buffer
            return buffer

    async def _execute_console_command(self, bid: str, command_line: str) -> dict[str, Any] | None:
        encoded_bid = _encoded_beacon_id(bid)
        parts = command_line.strip().split(None, 1)
        payload = {"command": parts[0]}
        if len(parts) > 1 and parts[1]:
            payload["arguments"] = parts[1]

        result = await self.cs_client.request_json(
            "POST",
            f"/api/v1/beacons/{encoded_bid}/consoleCommand",
            json=payload,
        )
        if result.get("ok"):
            data = result.get("data")
            return data if isinstance(data, dict) else {"result": data}

        if result.get("status_code") == 400:
            exception = result.get("exception")
            if isinstance(exception, str) and exception:
                try:
                    data = json.loads(exception)
                    name = data.get("name")
                    message = data.get("message")
                    if name and message:
                        return {"error": f"{name}: {message}"}
                except ValueError:
                    pass
            return {"error": "Bad Request (400)"}

        return result

    async def _build_wait_profile(self, bid: str, requested_timeout_seconds: float) -> dict[str, Any]:
        beacon = await self._fetch_beacon(bid)
        sleep_seconds = _extract_sleep_seconds(beacon)
        jitter_percent = _extract_jitter_percent(beacon)
        last_checkin_ms = _extract_last_checkin_ms(beacon)
        worst_case_sleep = sleep_seconds * (1.0 + (jitter_percent / 100.0))
        sleep_adjusted_timeout = (
            worst_case_sleep * DEFAULT_SLEEP_WAIT_CYCLES + DEFAULT_SLEEP_WAIT_MARGIN_SECONDS
            if worst_case_sleep > 0
            else 0.0
        )
        effective_timeout = max(float(requested_timeout_seconds), sleep_adjusted_timeout)
        notice = _build_sleep_notice(
            requested_timeout_seconds=float(requested_timeout_seconds),
            effective_timeout_seconds=effective_timeout,
            worst_case_sleep_seconds=worst_case_sleep,
            sleep_seconds=sleep_seconds,
            jitter_percent=jitter_percent,
        )

        return {
            "requested_timeout_seconds": requested_timeout_seconds,
            "effective_timeout_seconds": effective_timeout,
            "sleep_seconds": sleep_seconds,
            "jitter_percent": jitter_percent,
            "worst_case_sleep_seconds": worst_case_sleep,
            "last_checkin_ms": last_checkin_ms,
            "sleep_adjusted_timeout_seconds": sleep_adjusted_timeout,
            "strategy": "max(requested_timeout, worst_case_sleep * 2 + 30s)",
            "notice": notice,
        }

    async def _fetch_beacon(self, bid: str) -> dict[str, Any] | None:
        encoded_bid = _encoded_beacon_id(bid)
        detail = await self.cs_client.request_json("GET", f"/api/v1/beacons/{encoded_bid}")
        if detail.get("ok") and isinstance(detail.get("data"), dict):
            return detail["data"]
        logger.debug("Failed to fetch beacon detail for %s: %s", bid, detail.get("error"))

        beacon_list = await self.cs_client.request_json("GET", "/api/v1/beacons")
        if beacon_list.get("ok") and isinstance(beacon_list.get("data"), list):
            for beacon in beacon_list["data"]:
                if isinstance(beacon, dict) and str(beacon.get("bid")) == str(bid):
                    return beacon
        logger.debug("Failed to fetch beacon list while resolving %s: %s", bid, beacon_list.get("error"))
        return None

    async def _wait_for_console_result(
        self,
        *,
        buffer: StreamBuffer,
        cursor: int,
        timeout_seconds: float,
        quiet_seconds: float,
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        last_entries: list[dict[str, Any]] = []

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return last_entries

            output_result = await asyncio.to_thread(
                buffer.wait_for_quiet_result,
                cursor,
                remaining,
                quiet_seconds,
            )
            entries = output_result["entries"]
            last_entries = entries
            if any(_is_substantive_console_output(entry.get("data", "")) for entry in entries):
                return entries

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return entries
            await asyncio.to_thread(
                buffer.wait_for_entries,
                output_result["last_sequence"],
                min(remaining, 0.5),
            )

    async def _wait_for_task_terminal(
        self,
        *,
        task_result: dict[str, Any] | None,
        timeout_seconds: float,
        poll_seconds: float = 0.5,
    ) -> dict[str, Any]:
        task_path = _task_status_path(task_result)
        if not task_path:
            return {
                "task": task_result,
                "timed_out": False,
                "remaining_seconds": timeout_seconds,
                "note": "Task status URL was not present in command response",
            }

        deadline = time.monotonic() + max(0.1, timeout_seconds)
        last_task: dict[str, Any] | None = task_result
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "task": last_task,
                    "timed_out": True,
                    "remaining_seconds": 0.0,
                }

            result = await self.cs_client.request_json("GET", task_path)
            if result.get("ok") and isinstance(result.get("data"), dict):
                data = result["data"]
                last_task = data
                if _task_is_terminal(data):
                    return {
                        "task": data,
                        "timed_out": False,
                        "remaining_seconds": max(0.0, deadline - time.monotonic()),
                    }
            elif not result.get("ok"):
                last_task = {
                    "error": result.get("error"),
                    "statusUrl": task_path,
                }

            await asyncio.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

    def _streams_available(self) -> bool:
        return self.enabled and websocket is not None

    def _unavailable_message(self) -> str:
        if not self.enabled:
            return "Cobalt Strike WebSocket streams are disabled by configuration"
        if websocket is None:
            return "Missing dependency: websocket-client"
        return "Cobalt Strike WebSocket streams are unavailable"

    def _unavailable_result(self, stream: str) -> dict[str, Any]:
        return {
            "stream": stream,
            "error": self._unavailable_message(),
            "entries": [],
        }


_ANSI_RE = re.compile(r"\x1b\[[0-9;:]*[A-Za-z]")


def _is_substantive_console_output(data: Any) -> bool:
    text = _ANSI_RE.sub("", str(data)).strip()
    if not text:
        return False
    lower_text = text.lower()
    if "beacon>" in lower_text:
        return False
    if lower_text.startswith("[*] tasked beacon"):
        return False
    return True


def _task_status_path(task_result: dict[str, Any] | None) -> str | None:
    if not isinstance(task_result, dict):
        return None
    status_url = task_result.get("statusUrl")
    if isinstance(status_url, str) and status_url.startswith("/"):
        return status_url
    task_id = task_result.get("taskId") or task_result.get("id")
    if task_id:
        return f"/api/v1/tasks/{task_id}"
    return None


def _task_id(task_result: dict[str, Any] | None) -> Any:
    if not isinstance(task_result, dict):
        return None
    return task_result.get("taskId") or task_result.get("id")


def _task_is_terminal(task: dict[str, Any] | None) -> bool:
    if not isinstance(task, dict):
        return False
    status = str(task.get("taskStatus") or task.get("status") or "").upper()
    if status in TASK_TERMINAL_STATUSES:
        return True
    if status and status not in TASK_IN_PROGRESS_STATUSES:
        return True
    return False


def _extract_sleep_seconds(beacon: dict[str, Any] | None) -> float:
    if not isinstance(beacon, dict):
        return 0.0
    sleep = beacon.get("sleep")
    if isinstance(sleep, dict):
        return _to_float(sleep.get("sleep"))
    return _to_float(sleep or beacon.get("sleepSeconds") or beacon.get("sleep_seconds"))


def _extract_jitter_percent(beacon: dict[str, Any] | None) -> float:
    if not isinstance(beacon, dict):
        return 0.0
    sleep = beacon.get("sleep")
    if isinstance(sleep, dict):
        return max(0.0, _to_float(sleep.get("jitter")))
    return max(0.0, _to_float(beacon.get("jitter") or beacon.get("jitterPercent") or beacon.get("jitter_percent")))


def _extract_last_checkin_ms(beacon: dict[str, Any] | None) -> float | None:
    if not isinstance(beacon, dict):
        return None
    value = beacon.get("lastCheckinMs") or beacon.get("last_checkin_ms")
    if value is None:
        return None
    return _to_float(value)


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _build_sleep_notice(
    *,
    requested_timeout_seconds: float,
    effective_timeout_seconds: float,
    worst_case_sleep_seconds: float,
    sleep_seconds: float,
    jitter_percent: float,
) -> str | None:
    if worst_case_sleep_seconds < LONG_SLEEP_NOTICE_THRESHOLD_SECONDS:
        return None
    if effective_timeout_seconds <= requested_timeout_seconds:
        return None
    return (
        "Beacon has a long sleep interval; command completion may take several check-ins. "
        f"Sleep={sleep_seconds:g}s, jitter={jitter_percent:g}%, "
        f"worst-case check-in interval is about {worst_case_sleep_seconds:g}s. "
        f"Wait timeout was extended from {requested_timeout_seconds:g}s "
        f"to {effective_timeout_seconds:g}s."
    )


def add_cobalt_strike_stream_tools(
    mcp_server: FastMCP,
    stream_manager: CobaltStrikeWebSocketStreamManager,
) -> None:
    """Add MCP tools backed by Cobalt Strike WebSocket streams."""

    @mcp_server.tool()
    async def startCobaltStrikeWebsocketStreams() -> str:
        """Start the default Cobalt Strike WebSocket subscriptions."""
        audit_event(
            "tool_invocation",
            tool_name="startCobaltStrikeWebsocketStreams",
            status="started",
        )
        stream_manager.start_defaults()
        result = stream_manager.status()
        audit_event(
            "tool_invocation",
            tool_name="startCobaltStrikeWebsocketStreams",
            status="completed",
            details={"enabled": result.get("enabled")},
        )
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def getCobaltStrikeWebsocketStatus() -> str:
        """Get current status for Cobalt Strike WebSocket stream subscriptions."""
        audit_event(
            "tool_invocation",
            tool_name="getCobaltStrikeWebsocketStatus",
            status="completed",
        )
        return json.dumps(stream_manager.status(), indent=2)

    @mcp_server.tool()
    async def getBeaconConsoleTail(bid: str, lines: int = 100) -> str:
        """Get recent streamed console output for a beacon."""
        result = stream_manager.beaconlog_tail(bid, lines)
        audit_event(
            "tool_invocation",
            tool_name="getBeaconConsoleTail",
            beacon_id=result.get("bid") or bid,
            status="completed" if not result.get("error") else "failed",
            details={"lines": lines},
        )
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def getRecentEventLogTail(lines: int = 100) -> str:
        """Get recent streamed Cobalt Strike event log output."""
        result = stream_manager.eventlog_tail(lines)
        audit_event(
            "tool_invocation",
            tool_name="getRecentEventLogTail",
            status="completed" if not result.get("error") else "failed",
            details={"lines": lines},
        )
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def getLiveBeaconSnapshot() -> str:
        """Get the latest streamed beacon snapshot."""
        result = stream_manager.beacons_snapshot()
        audit_event(
            "tool_invocation",
            tool_name="getLiveBeaconSnapshot",
            status="completed" if not result.get("error") else "failed",
        )
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def executeBeaconConsoleAndWait(
        bid: str,
        command_line: str,
        timeout_seconds: float = 60.0,
        quiet_seconds: float = 1.0,
    ) -> str:
        """Execute a beacon console command and wait for streamed console output."""
        result = await stream_manager.execute_console_and_wait(
            bid=bid,
            command_line=command_line,
            timeout_seconds=timeout_seconds,
            quiet_seconds=quiet_seconds,
        )
        return json.dumps(result, indent=2)

    logger.info("Added MCP WebSocket stream tools")
