"""An in-memory team server behind ``CobaltStrikeClient``'s method surface.

Records are seeded in the camelCase shapes the REST API lists. A beacon's answer lands when
its scheduled time passes on the virtual clock, and ``fail`` injects the exceptions the
real client raises.
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from typing import Any

import aiohttp
from cs_sdk_python.api_client.exceptions import ApiException

from tests.virtual_time import VirtualClock

GLOBAL_CATALOG = "0"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def api_error(status: int, detail: str | None = None) -> ApiException:
    """``detail`` None is the empty body a live server sends with most 404s."""
    body = "" if detail is None else json.dumps({"message": detail})
    return ApiException(status=status, reason=HTTPStatus(status).phrase, body=body)


def connection_failure() -> aiohttp.ClientConnectionError:
    return aiohttp.ClientConnectionError("Cannot connect to host teamserver.example:50443")


@dataclass
class FakeBinaryStream:
    media_type: str
    filename: str | None
    content_length: int | None
    data: bytes

    async def chunks(self, size: int = 65_536) -> AsyncIterator[bytes]:
        for start in range(0, len(self.data), size):
            yield self.data[start : start + size]

    async def aclose(self) -> None:
        pass


@dataclass
class _Answer:
    task_id: str
    at: datetime
    output: str | None


class FakeTeamServer:
    def __init__(self, clock: VirtualClock) -> None:
        self.clock = clock
        self.username = "mcp-service"
        self.beacons: dict[str, dict[str, Any]] = {}
        self.catalog: list[dict[str, Any]] = []
        self.tasks: dict[str, dict[str, Any]] = {}
        self.artifacts: list[dict[str, Any]] = []
        self.downloads: list[dict[str, Any]] = []
        self.active_downloads: dict[str, list[dict[str, Any]]] = {}
        self.screenshots: list[dict[str, Any]] = []
        # (resource, id) -> (media type, suggested file name, bytes)
        self.files: dict[tuple[str, str], tuple[str, str | None, bytes]] = {}
        self.job_commands = {"execute-assembly", "powershell", "powerpick", "keylogger"}
        self.submissions: list[dict[str, Any]] = []
        self.logins = 0
        self._answers: list[_Answer] = []
        self._failures: dict[str, BaseException] = {}
        self._task_counter = 0
        self._job_counter = 0

    def fail(self, method: str, exc: BaseException) -> None:
        """Raise ``exc`` from the next call of ``method`` only."""
        self._failures[method] = exc

    def _check(self, method: str) -> None:
        exc = self._failures.pop(method, None)
        if exc is not None:
            raise exc

    # Seeding

    def add_beacon(
        self,
        bid: str = "1234",
        *,
        alive: bool = True,
        sleep_seconds: int = 5,
        hostname: str = "WS01",
        username: str = "alice",
        last_checkin: datetime | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        checked_in = self.clock.now() if last_checkin is None else last_checkin
        record = {
            "bid": bid,
            "pbid": "",
            "computer": hostname,
            "user": username,
            "isAdmin": False,
            "process": "explorer.exe",
            "pid": 4242,
            "listener": "https-main",
            "alive": alive,
            "lastCheckinTime": self.clock.epoch_ms(checked_in),
            "note": note,
            "internal": "10.0.0.5",
            "external": "203.0.113.9",
            "host": "10.0.0.5",
            "version": "10.0",
            "build": 19045,
            "systemArch": "x64",
            "beaconArch": "x64",
            "impersonated": "",
            "pivotHint": "",
            "port": 0,
            "supportsSleep": True,
            "linkState": None,
            "session": "beacon",
            "sleep": {"sleep": sleep_seconds, "jitter": 10},
        }
        self.beacons[bid] = record
        return record

    def add_command(
        self, name: str, *, groups: Sequence[str] = ("builtin",), description: str | None = None
    ) -> dict[str, Any]:
        row = {
            "name": name,
            "description": f"{name} help" if description is None else description,
            "details": f"Use: {name} [arguments]",
            "groups": list(groups),
        }
        self.catalog.append(row)
        return row

    def add_task(
        self,
        task_id: str,
        *,
        bid: str,
        command_line: str,
        status: str = "COMPLETED",
        output: str | None = None,
        errors: Iterable[str] = (),
        created: datetime | None = None,
        updated: datetime | None = None,
        jid: int | None = None,
        acknowledged: bool = True,
        user: str = "operator",
    ) -> dict[str, Any]:
        created_at = self.clock.now() if created is None else created
        task = {
            "taskId": task_id,
            "bid": bid,
            "taskStatus": status,
            "taskCommand": command_line,
            "user": user,
            "created": self.clock.epoch_ms(created_at),
            "updated": self.clock.epoch_ms(updated) if updated is not None else 0,
            "jid": jid,
            "tactics": [],
            "taskAcknowledgements": (
                [{"text": f"Tasked beacon to run: {command_line}", "tactics": []}]
                if acknowledged
                else []
            ),
            "result": [{"type": "text", "output": output}] if output is not None else [],
            "error": [{"message": message} for message in errors],
        }
        self.tasks[task_id] = task
        return task

    def add_download(
        self,
        download_id: str,
        *,
        bid: str,
        name: str,
        path: str,
        data: bytes,
        downloaded_at: datetime | None = None,
    ) -> dict[str, Any]:
        moment = self.clock.now() if downloaded_at is None else downloaded_at
        row = {
            "id": download_id,
            "bid": bid,
            "name": name,
            "path": path,
            "timestamp": self.clock.epoch_ms(moment),
            "size": len(data),
        }
        self.downloads.append(row)
        self.files[("download", download_id)] = ("application/octet-stream", name, data)
        return row

    def add_active_download(
        self, bid: str, *, name: str, path: str, size: int, received: int
    ) -> dict[str, Any]:
        row = {"name": name, "path": path, "size": size, "received": received}
        self.active_downloads.setdefault(bid, []).append(row)
        return row

    def add_screenshot(
        self, screenshot_id: str, *, bid: str, title: str, created_at: datetime | None = None
    ) -> dict[str, Any]:
        """Served as octet-stream named screenshot.jpg, as a live team server does."""
        beacon = self.beacons.get(bid, {})
        moment = self.clock.now() if created_at is None else created_at
        row = {
            "id": screenshot_id,
            "bid": bid,
            "computer": beacon.get("computer"),
            "user": beacon.get("user"),
            "title": title,
            "timestamp": self.clock.epoch_ms(moment),
        }
        self.screenshots.append(row)
        self.files[("screenshot", screenshot_id)] = (
            "application/octet-stream",
            "screenshot.jpg",
            PNG_BYTES,
        )
        return row

    def add_artifact(self, reference: str, *, key: str | None = None) -> dict[str, Any]:
        row = {
            "symbolicReference": reference,
            "key": reference.removeprefix("@artifacts/") if key is None else key,
        }
        self.artifacts.append(row)
        return row

    def beacon_answers(self, task_id: str, *, at: datetime | None = None, output: str) -> None:
        """Once ``at`` passes on the clock the task completes and the beacon checks in."""
        self._answers.append(_Answer(task_id, self.clock.now() if at is None else at, output))
        self._deliver_due()

    def _deliver_due(self) -> None:
        now = self.clock.now()
        for answer in sorted((a for a in self._answers if a.at <= now), key=lambda a: a.at):
            task = self.tasks[answer.task_id]
            task["result"].append({"type": "text", "output": answer.output})
            task["taskStatus"] = "COMPLETED"
            task["updated"] = self.clock.epoch_ms(answer.at)
            beacon = self.beacons.get(task["bid"])
            if beacon is not None:
                beacon["lastCheckinTime"] = max(
                    beacon["lastCheckinTime"], self.clock.epoch_ms(answer.at)
                )
        self._answers = [a for a in self._answers if a.at > now]

    def _served_beacon(self, record: Mapping[str, Any]) -> dict[str, Any]:
        age_ms = max(0, self.clock.epoch_ms(self.clock.now()) - record["lastCheckinTime"])
        return {
            **copy.deepcopy(record),
            "lastCheckinMs": age_ms,
            "lastCheckinFormatted": f"{age_ms // 1000}s",
        }

    def _catalog_for(self, bid: str) -> list[dict[str, Any]]:
        if bid != GLOBAL_CATALOG and bid not in self.beacons:
            raise api_error(404)
        return self.catalog

    @staticmethod
    def _summary(task: Mapping[str, Any]) -> dict[str, Any]:
        # Summaries omit the arrays only the detail endpoint carries.
        return {
            key: copy.deepcopy(value)
            for key, value in task.items()
            if key not in {"result", "error", "taskAcknowledgements"}
        }

    def _console_task(
        self, bid: str, command_line: str, *, status: str, jid: int | None = None
    ) -> dict[str, Any]:
        self._task_counter += 1
        task_id = f"{self._task_counter:x}-{bid}"
        self.tasks[task_id] = {
            "taskId": task_id,
            "bid": bid,
            "taskStatus": status,
            "taskCommand": command_line,
            "user": self.username,
            "created": self.clock.epoch_ms(self.clock.now()),
            "updated": 0,
            "jid": jid,
            "tactics": [],
            "taskAcknowledgements": [
                {"text": f"Tasked beacon to run: {command_line}", "tactics": []}
            ],
            "result": [],
            "error": [],
        }
        return self.tasks[task_id]

    # The client's method surface

    async def __aenter__(self) -> FakeTeamServer:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        pass

    async def login(self) -> None:
        self.logins += 1
        self._check("login")

    async def get_teamserver_ip(self) -> str:
        return "10.0.0.1"

    async def list_beacons(self) -> list[dict[str, Any]]:
        self._check("list_beacons")
        self._deliver_due()
        return [self._served_beacon(record) for record in self.beacons.values()]

    async def get_beacon(self, bid: str) -> dict[str, Any]:
        self._check("get_beacon")
        self._deliver_due()
        record = self.beacons.get(bid)
        if record is None:
            raise api_error(404)
        return self._served_beacon(record)

    async def list_beacon_commands(self, bid: str) -> list[dict[str, Any]]:
        self._check("list_beacon_commands")
        return [copy.deepcopy(row) for row in self._catalog_for(bid)]

    async def get_beacon_command(self, bid: str, command: str) -> dict[str, Any]:
        self._check("get_beacon_command")
        row = next((row for row in self._catalog_for(bid) if row["name"] == command), None)
        if row is None:
            raise api_error(404)
        return copy.deepcopy(row)

    async def list_jump_techniques(self, bid: str) -> list[dict[str, Any]]:
        return []

    async def list_remote_exec_techniques(self, bid: str) -> list[dict[str, Any]]:
        return []

    async def list_elevate_techniques(self, bid: str) -> list[dict[str, Any]]:
        return []

    async def list_runasadmin_techniques(self, bid: str) -> list[dict[str, Any]]:
        return []

    async def list_listeners(self) -> list[dict[str, Any]]:
        return []

    async def execute_console_command(
        self, bid: str, *, command: str, arguments: str | None
    ) -> dict[str, Any]:
        # Like a live server, accepts a beacon ID it does not list.
        self._check("execute_console_command")
        self.submissions.append({"beacon_id": bid, "command": command, "arguments": arguments})
        command_line = command if not arguments else f"{command} {arguments}"
        jid = None
        if command in self.job_commands:
            self._job_counter += 1
            jid = self._job_counter
        task = self._console_task(bid, command_line, status="IN_PROGRESS", jid=jid)
        return {
            "name": command,
            "status": "SUCCESS",
            "message": f"Tasked beacon {bid}",
            "taskId": task["taskId"],
        }

    async def list_tasks(self) -> list[dict[str, Any]]:
        self._check("list_tasks")
        self._deliver_due()
        return [self._summary(task) for task in self.tasks.values()]

    async def list_beacon_tasks(self, bid: str) -> list[dict[str, Any]]:
        self._check("list_beacon_tasks")
        self._deliver_due()
        if bid not in self.beacons:
            raise api_error(404)
        return [self._summary(task) for task in self.tasks.values() if task["bid"] == bid]

    async def get_task(self, task_id: str) -> dict[str, Any]:
        self._check("get_task")
        self._deliver_due()
        task = self.tasks.get(task_id)
        if task is None:
            raise api_error(404)
        return copy.deepcopy(task)

    async def list_artifacts(self) -> list[dict[str, Any]]:
        self._check("list_artifacts")
        return [copy.deepcopy(row) for row in self.artifacts]

    async def list_downloads(self) -> list[dict[str, Any]]:
        self._check("list_downloads")
        return [copy.deepcopy(row) for row in self.downloads]

    async def list_active_downloads(self, bid: str) -> list[dict[str, Any]]:
        self._check("list_active_downloads")
        return [copy.deepcopy(row) for row in self.active_downloads.get(bid, [])]

    async def open_download_file(self, download_id: str) -> FakeBinaryStream:
        self._check("open_download_file")
        return self._open("download", download_id)

    async def list_screenshots(self) -> list[dict[str, Any]]:
        self._check("list_screenshots")
        return [copy.deepcopy(row) for row in self.screenshots]

    async def open_screenshot_image(self, screenshot_id: str) -> FakeBinaryStream:
        self._check("open_screenshot_image")
        return self._open("screenshot", screenshot_id)

    def _open(self, resource: str, content_id: str) -> FakeBinaryStream:
        entry = self.files.get((resource, content_id))
        if entry is None:
            raise api_error(404)
        media_type, filename, data = entry
        return FakeBinaryStream(media_type, filename, len(data), data)
