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
from typing import Any
from urllib.parse import urlparse, urlunparse

try:
    import websocket
except ImportError:  # pragma: no cover - exercised only when dependency is absent
    websocket = None

from fastmcp import FastMCP

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


def build_connect_frame(token: str, host: str) -> str:
    return f"CONNECT\nAuthorization:Bearer {token}\naccept-version:1.2\nhost:{host}\n\n\x00"


def build_subscribe_frame(destination: str, frame_id: int = 1, ack: str = "auto") -> str:
    return f"SUBSCRIBE\nid:{frame_id}\ndestination:{destination}\nack:{ack}\n\n\x00"


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
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        quiet_seconds = max(0.0, quiet_seconds)
        last_count = -1
        last_change = time.monotonic()

        with self._condition:
            while True:
                entries = [entry for entry in self._entries if entry.sequence > after_sequence]
                now = time.monotonic()

                if len(entries) != last_count:
                    last_count = len(entries)
                    last_change = now

                if entries and now - last_change >= quiet_seconds:
                    return [entry.to_dict() for entry in entries]

                remaining = deadline - now
                if remaining <= 0:
                    return [entry.to_dict() for entry in entries]

                wait_for = min(remaining, quiet_seconds or remaining, 0.25)
                self._condition.wait(wait_for)


class CobaltStrikeWebSocketStream:
    def __init__(
        self,
        *,
        ws_url: str,
        host: str,
        token: str,
        destination: str,
        verify_tls: bool,
        reconnect_seconds: float,
        on_payload,
    ):
        self.ws_url = ws_url
        self.host = host
        self.token = token
        self.destination = destination
        self.verify_tls = verify_tls
        self.reconnect_seconds = reconnect_seconds
        self.on_payload = on_payload
        self.status = "initialized"
        self.last_error = ""
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._ws = None

    def start(self) -> None:
        if websocket is None:
            self.status = "dependency_missing"
            self.last_error = "Missing dependency: websocket-client"
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"cs-ws-{self.destination}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass

    def to_status(self) -> dict[str, Any]:
        return {
            "destination": self.destination,
            "status": self.status,
            "last_error": self.last_error,
            "alive": bool(self._thread and self._thread.is_alive()),
        }

    def _on_message(self, _ws, message: str) -> None:
        frame = parse_stomp_frame(message)
        command = frame.get("command")
        if command == "ERROR":
            self.status = "error"
            self.last_error = self._format_error(frame)
            return
        if command == "CONNECTED":
            self.status = "connected"
            return
        body = frame.get("body")
        if body is not None:
            self.on_payload(body)

    def _on_error(self, _ws, error: Any) -> None:
        self.status = "error"
        self.last_error = str(error)

    def _on_close(self, _ws, _close_status_code, _close_msg) -> None:
        if not self._stop_event.is_set():
            self.status = "disconnected"

    def _on_open(self, ws) -> None:
        self.status = "connected"
        ws.send(build_connect_frame(self.token, self.host))
        ws.send(build_subscribe_frame(self.destination))

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.status = "connecting"
                self._ws = websocket.WebSocketApp(
                    self.ws_url,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open,
                    header=[f"Authorization: Bearer {self.token}"],
                )
                self._ws.run_forever(
                    sslopt={
                        "cert_reqs": ssl.CERT_REQUIRED if self.verify_tls else ssl.CERT_NONE,
                    }
                )
            except Exception as exc:  # pylint: disable=broad-except
                self.status = "error"
                self.last_error = str(exc)
            finally:
                self._ws = None

            if not self._stop_event.is_set():
                time.sleep(max(0.1, self.reconnect_seconds))

        self.status = "stopped"

    @staticmethod
    def _format_error(frame: dict[str, Any]) -> str:
        body = frame.get("body")
        if isinstance(body, dict):
            return body.get("message") or body.get("error") or json.dumps(body)
        return str(body) if body else "stream error"


class CobaltStrikeWebSocketStreamManager:
    def __init__(
        self,
        cs_client: CobaltStrikeClient,
        *,
        auto_start: bool = False,
        buffer_size: int = 1000,
        reconnect_seconds: float = 2.0,
    ):
        self.cs_client = cs_client
        self.auto_start = auto_start
        self.buffer_size = max(100, buffer_size)
        self.reconnect_seconds = reconnect_seconds
        self._lock = threading.Lock()
        self._eventlog = StreamBuffer(self.buffer_size)
        self._beacon_logs: dict[str, StreamBuffer] = {}
        self._beacons_payload: Any = None
        self._beacons_updated_at: float | None = None
        self._streams: dict[str, CobaltStrikeWebSocketStream] = {}

    def start_defaults(self) -> None:
        self.ensure_eventlog_stream()
        self.ensure_beacons_stream()

    def stop_all(self) -> None:
        with self._lock:
            streams = list(self._streams.values())
        for stream in streams:
            stream.stop()

    def ensure_eventlog_stream(self) -> None:
        self._ensure_stream(
            EVENTLOG_DESTINATION,
            lambda body: [self._eventlog.append(line) for line in _extract_rendered_output(body)],
        )

    def ensure_beacons_stream(self) -> None:
        def on_beacons(body: Any) -> None:
            with self._lock:
                self._beacons_payload = body
                self._beacons_updated_at = time.time()

        self._ensure_stream(BEACONS_DESTINATION, on_beacons)

    def ensure_beaconlog_stream(self, bid: str) -> None:
        destination = BEACONLOG_DESTINATION_TEMPLATE.format(bid=bid)
        buffer = self._beacon_buffer(bid)
        self._ensure_stream(
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
        if not self._streams_available():
            return self._unavailable_result(BEACONLOG_DESTINATION_TEMPLATE.format(bid=bid))
        self.ensure_beaconlog_stream(bid)
        return {
            "stream": BEACONLOG_DESTINATION_TEMPLATE.format(bid=bid),
            "entries": self._beacon_buffer(bid).tail(lines),
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
        if not self._streams_available():
            return {
                "error": self._unavailable_message(),
                "bid": bid,
                "command_line": command_line,
                "task_submitted": False,
            }
        if not command_line.strip():
            return {"error": "command_line cannot be empty"}

        self.ensure_beaconlog_stream(bid)
        buffer = self._beacon_buffer(bid)
        cursor = buffer.sequence
        wait_profile = await self._build_wait_profile(bid, timeout_seconds)
        effective_timeout_seconds = wait_profile["effective_timeout_seconds"]

        task_result = await self._execute_console_command(bid, command_line)
        if isinstance(task_result, dict) and task_result.get("error"):
            return {
                "bid": bid,
                "command_line": command_line,
                "task": task_result,
                "wait_profile": wait_profile,
                "output": [],
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
        entries = await asyncio.to_thread(
            buffer.wait_for_quiet,
            cursor,
            min(max(quiet_seconds, 0.1) + 1.0, remaining if not task_completed else max(quiet_seconds, 0.1) + 1.0),
            quiet_seconds,
        )
        return {
            "bid": bid,
            "command_line": command_line,
            "task": task_result,
            "task_detail": task_detail.get("task"),
            "wait_profile": wait_profile,
            "output": entries,
            "timed_out": task_detail.get("timed_out", False),
            "task_completed": task_completed,
            "output_complete": task_completed and not task_detail.get("timed_out", False),
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            streams = {name: stream.to_status() for name, stream in self._streams.items()}
            beacon_buffers = {
                bid: {"sequence": buffer.sequence, "entries": len(buffer.tail(self.buffer_size))}
                for bid, buffer in self._beacon_logs.items()
            }
        return {
            "enabled": True,
            "dependency_available": websocket is not None,
            "base_url": self.cs_client.base_url,
            "streams": streams,
            "buffers": {
                "eventlog_sequence": self._eventlog.sequence,
                "beacon_logs": beacon_buffers,
            },
        }

    def _ensure_stream(self, destination: str, on_payload) -> None:
        if websocket is None:
            return
        with self._lock:
            existing = self._streams.get(destination)
            if existing:
                existing.start()
                return

            ws_url, host = _websocket_url_from_base_url(self.cs_client.base_url)
            stream = CobaltStrikeWebSocketStream(
                ws_url=ws_url,
                host=host,
                token=self.cs_client.access_token,
                destination=destination,
                verify_tls=self.cs_client.verify_tls,
                reconnect_seconds=self.reconnect_seconds,
                on_payload=on_payload,
            )
            self._streams[destination] = stream
            stream.start()

    def _beacon_buffer(self, bid: str) -> StreamBuffer:
        with self._lock:
            buffer = self._beacon_logs.get(bid)
            if buffer is None:
                buffer = StreamBuffer(self.buffer_size)
                self._beacon_logs[bid] = buffer
            return buffer

    async def _execute_console_command(self, bid: str, command_line: str) -> dict[str, Any] | None:
        parts = command_line.strip().split(" ", 1)
        payload = {"command": parts[0]}
        if len(parts) > 1 and parts[1]:
            payload["arguments"] = parts[1]

        client = self.cs_client.get_authenticated_client()
        try:
            response = await client.post(f"/api/v1/beacons/{bid}/consoleCommand", json=payload)
            if response.status_code == 400:
                try:
                    data = response.json()
                    name = data.get("name")
                    message = data.get("message")
                    if name and message:
                        return {"error": f"{name}: {message}"}
                except ValueError:
                    pass
                return {"error": "Bad Request (400)"}
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # pylint: disable=broad-except
            return {"error": str(exc)}

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
        client = self.cs_client.get_authenticated_client()
        try:
            response = await client.get(f"/api/v1/beacons/{bid}")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    return data
        except Exception:
            logger.debug("Failed to fetch beacon detail for %s", bid, exc_info=True)

        try:
            response = await client.get("/api/v1/beacons")
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                for beacon in data:
                    if isinstance(beacon, dict) and str(beacon.get("bid")) == str(bid):
                        return beacon
        except Exception:
            logger.debug("Failed to fetch beacon list while resolving %s", bid, exc_info=True)
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

            entries = await asyncio.to_thread(
                buffer.wait_for_quiet,
                cursor,
                remaining,
                quiet_seconds,
            )
            last_entries = entries
            if any(_is_substantive_console_output(entry.get("data", "")) for entry in entries):
                return entries

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return entries
            await asyncio.to_thread(buffer.wait_for_entries, cursor + len(entries), min(remaining, 0.5))

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
        client = self.cs_client.get_authenticated_client()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "task": last_task,
                    "timed_out": True,
                    "remaining_seconds": 0.0,
                }

            try:
                response = await client.get(task_path)
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict):
                    last_task = data
                    if _task_is_terminal(data):
                        return {
                            "task": data,
                            "timed_out": False,
                            "remaining_seconds": max(0.0, deadline - time.monotonic()),
                        }
            except Exception as exc:  # pylint: disable=broad-except
                last_task = {
                    "error": str(exc),
                    "statusUrl": task_path,
                }

            await asyncio.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

    def _streams_available(self) -> bool:
        return websocket is not None

    def _unavailable_message(self) -> str:
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
        stream_manager.start_defaults()
        return json.dumps(stream_manager.status(), indent=2)

    @mcp_server.tool()
    async def getCobaltStrikeWebsocketStatus() -> str:
        """Get current status for Cobalt Strike WebSocket stream subscriptions."""
        return json.dumps(stream_manager.status(), indent=2)

    @mcp_server.tool()
    async def getBeaconConsoleTail(bid: str, lines: int = 100) -> str:
        """Get recent streamed console output for a beacon."""
        result = stream_manager.beaconlog_tail(bid, lines)
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def getRecentEventLogTail(lines: int = 100) -> str:
        """Get recent streamed Cobalt Strike event log output."""
        result = stream_manager.eventlog_tail(lines)
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def getLiveBeaconSnapshot() -> str:
        """Get the latest streamed beacon snapshot."""
        result = stream_manager.beacons_snapshot()
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
