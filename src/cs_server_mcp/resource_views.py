"""Present beacons, artifacts, downloads, and screenshots as the tools publish them.

Every record leads with its identifier under the name the tools take it by. Cobalt Strike
lists these records whole, with no server-side filter or paging, so the local regex
search, offset paging, and single-record lookup the list tools share live here too.
"""

from __future__ import annotations

import stat
import time
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import regex
from mcp.server.mcpserver.exceptions import ToolError

from cs_server_mcp import agent_text
from cs_server_mcp.client import CobaltStrikeResponseError
from cs_server_mcp.command_errors import CommandSelectionError
from cs_server_mcp.config import SEARCH_REGEX_BUDGET_SECONDS, SEARCH_REGEX_MAX_CHARS, Settings
from cs_server_mcp.tool_errors import InvalidArgument, InvalidSearchRegex

_BEACON_FIELDS = {
    "computer": "hostname",
    "user": "username",
    "isAdmin": "is_admin",
    "process": "process_name",
    "pid": "process_id",
    "listener": "listener",
    "alive": "alive",
    "lastCheckinFormatted": "last_checkin_age",
    "note": "note",
    "internal": "internal_ip",
    "external": "external_ip",
    "host": "host_ip",
    "version": "os_version",
    "build": "os_build",
    "systemArch": "system_arch",
    "beaconArch": "architecture_type",
    "impersonated": "impersonated_as",
    "pivotHint": "pivot_hint",
    "port": "ssh_port",
    "supportsSleep": "supports_sleep",
    "linkState": "link_state",
}
_BEACON_ROW_FIELDS = (
    "beacon_id",
    "parent_beacon_id",
    "hostname",
    "username",
    "is_admin",
    "process_name",
    "process_id",
    "listener",
    "alive",
    "last_seen_at",
    "last_checkin_age",
    "note",
)


def present_beacon(row: Mapping[str, Any]) -> dict[str, Any]:
    beacon_id = identifier(row, "bid")
    sleep = row.get("sleep") or {}
    if not isinstance(sleep, Mapping):
        raise CobaltStrikeResponseError(agent_text.INVALID_BEACON_SLEEP)
    data = {
        "beacon_id": beacon_id,
        "parent_beacon_id": str(row["pbid"]) if row.get("pbid") else None,
        **{new: row.get(old) for old, new in _BEACON_FIELDS.items()},
        "last_seen_at": isoformat(row.get("lastCheckinTime")),
        "sleep_seconds": sleep.get("sleep"),
        "jitter_percent": sleep.get("jitter"),
    }
    if data["link_state"] is not None:
        data["link_state"] = str(data["link_state"]).lower()
    if data["note"] is None:
        data["note"] = ""
    # The team server fills these with empty strings and a zero port when they do not apply.
    for key in ("impersonated_as", "pivot_hint"):
        if not data[key]:
            del data[key]
    if not data["ssh_port"] or row.get("session") != "ssh":
        del data["ssh_port"]
    return data


# How long after its last check-in a beacon marked dead is said to be possibly busy rather
# than lost. A beacon cannot check in while it runs an inline task, and Cobalt Strike marks
# it dead a few sleeps later (a 5-second-sleep lab beacon was marked dead 15 to 18 seconds
# into a 20-second BOF, then came back). Not scaled by the sleep: it bounds how long a task
# plausibly blocks a beacon, which the sleep does not change.
RECENT_CHECKIN_MISS_SECONDS = 120.0


def checkin_age_ms(beacon: Mapping[str, Any]) -> int | None:
    """Check-in age by the team server's own clock, so no clock of this host is involved."""
    value = beacon.get("lastCheckinMs")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def recent_checkin_miss(checkin_ms: int | None) -> bool:
    if checkin_ms is None:
        return False
    return checkin_ms <= RECENT_CHECKIN_MISS_SECONDS * 1000


def present_beacon_list(
    rows: Sequence[Mapping[str, Any]],
    *,
    include_dead: bool = False,
) -> list[dict[str, Any]]:
    """Rows cut to their identifying fields, alive first, then by beacon_id.

    A beacon marked dead stays listed while its miss is recent, since one that vanished
    mid-task would read as lost. Check-in times are not a sort key: they change between
    calls and would move beacons across offset pages.
    """
    beacons = [
        present_beacon(row)
        for row in rows
        if include_dead or row.get("alive") is True or recent_checkin_miss(checkin_age_ms(row))
    ]
    beacons.sort(key=lambda row: (row["alive"] is not True, identifier_sort_key(row["beacon_id"])))
    return [{key: row[key] for key in _BEACON_ROW_FIELDS} for row in beacons]


ARTIFACT_REFERENCE_PREFIX = "@artifacts/"


def present_artifact(row: Any) -> dict[str, Any]:
    # Cobalt Strike records nothing else about an artifact; its key repeats the reference.
    return {"artifact_reference": identifier(row, "symbolicReference")}


def present_artifact_size(row: Mapping[str, Any], directory: Path) -> dict[str, Any]:
    """Adds ``size_bytes`` from the file under the artifacts directory; a file the directory
    does not show leaves the row without a size rather than failing the listing."""
    size = _stored_artifact_size(directory, row["artifact_reference"])
    return dict(row) if size is None else {**row, "size_bytes": size}


def _stored_artifact_size(directory: Path, reference: str) -> int | None:
    """None when the reference would leave ``directory`` or names no regular file there."""
    if not reference.startswith(ARTIFACT_REFERENCE_PREFIX):
        return None
    relative = PurePosixPath(reference.removeprefix(ARTIFACT_REFERENCE_PREFIX))
    if relative.is_absolute() or any(part in {".", ".."} for part in relative.parts):
        return None
    try:
        status = (directory / relative).stat()
    except OSError:
        return None
    return status.st_size if stat.S_ISREG(status.st_mode) else None


def _remote_directory(path: Any) -> Any:
    """Strips the trailing separator Cobalt Strike adds, except on a drive root such as C:\\."""
    if not isinstance(path, str) or len(path) < 2 or path[-1] not in ("\\", "/"):
        return path
    return path if path[-2] == ":" else path[:-1]


def present_download(row: Mapping[str, Any], *, host: str | None = None) -> dict[str, Any]:
    """``host`` is the listed beacon's hostname; the team server records none on a download."""
    host = host or row.get("host")
    data = {
        "download_id": identifier(row, "id"),
        "transfer_state": "completed",
        "progress": 1.0,
        "beacon_id": identifier(row, "bid"),
        **({"host": host} if host else {}),
        "remote_file_name": row.get("name"),
        "remote_directory": _remote_directory(row.get("path")),
        "downloaded_at": isoformat(row.get("timestamp")),
    }
    # Cobalt Strike 4.13 records the size, but its API schema omits the field.
    size = row.get("size")
    if type(size) is int and size >= 0:
        data["size_bytes"] = size
    return data


def present_active_download(
    row: Mapping[str, Any], *, beacon_id: str, host: str | None
) -> dict[str, Any]:
    size, received = row.get("size"), row.get("received")
    if any(type(value) is not int or value < 0 for value in (size, received)):
        raise CobaltStrikeResponseError(agent_text.INVALID_ACTIVE_DOWNLOAD_BYTES)
    return {
        "download_id": None,
        "transfer_state": "in_progress",
        "beacon_id": beacon_id,
        **({"host": host} if host else {}),
        "remote_file_name": row["name"],
        "remote_directory": _remote_directory(row["path"]),
        "size_bytes": size,
        "received_bytes": received,
        "progress": min(received / size, 1.0) if size else None,
    }


def present_screenshot(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "screenshot_id": identifier(row, "id"),
        "beacon_id": identifier(row, "bid"),
        "hostname": row.get("computer"),
        "username": row.get("user"),
        "window_title": row.get("title"),
        "created_at": isoformat(row.get("timestamp")),
    }


def isoformat(value: Any) -> str | None:
    """ISO dates and Unix timestamps as UTC ISO 8601; malformed values are None.

    A timestamp at or before the epoch is None too: Cobalt Strike reports epoch zero as
    ``updated`` for a task it has not touched since creation.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = _parsed_instant(value)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        if parsed.timestamp() <= 0:
            return None
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _parsed_instant(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, (str, int, float)):
        return None
    try:
        epoch = float(value)
    except ValueError:
        return datetime.fromisoformat(value.strip())
    if epoch <= 0:
        return None
    # Below 100 billion the count is seconds; the API's millisecond fields are far larger.
    return datetime.fromtimestamp(epoch / 1000 if epoch >= 100_000_000_000 else epoch, UTC)


def identifier(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (str, int)) or str(value) == "":
        raise CobaltStrikeResponseError(agent_text.RECORD_WITHOUT_FIELD.format(field=field))
    return str(value)


def optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def timestamp_key(value: str | None) -> datetime:
    return datetime.fromisoformat(value) if value else datetime.min.replace(tzinfo=UTC)


def identifier_sort_key(value: str) -> tuple[int, int, str]:
    """Numeric IDs sort numerically, before opaque IDs sorted lexically."""
    return (0, int(value), value) if value.isdecimal() else (1, 0, value)


def sort_newest_first(rows: list[dict[str, Any]], *, timestamp_field: str, id_field: str) -> None:
    """In place: newest ``timestamp_field`` first, ties in ``id_field`` order. Two stable sorts,
    since the keys run in opposite directions."""
    rows.sort(key=lambda row: identifier_sort_key(row[id_field]))
    rows.sort(key=lambda row: timestamp_key(row[timestamp_field]), reverse=True)


def local_page(
    rows: Sequence[Mapping[str, Any]],
    *,
    limit: int | None,
    offset: int | None,
    resource: str,
    settings: Settings,
) -> dict[str, Any]:
    start = offset or 0
    if start < 0:
        raise InvalidArgument(agent_text.OFFSET_INVALID)
    size = settings.clamp_list_limit(limit, resource=resource)
    selected = list(rows[start : start + size])
    more = start + len(selected) < len(rows)
    return {
        "has_more": more,
        "next_offset": start + len(selected) if more else None,
        "total_records": len(rows),
        **({"limit_clamped_to": size} if limit is not None and limit > size else {}),
        "results": selected,
    }


def _compile_search_regex(pattern: str) -> regex.Pattern:
    if len(pattern) > SEARCH_REGEX_MAX_CHARS:
        raise InvalidSearchRegex(
            agent_text.SEARCH_REGEX_TOO_LONG.format(
                length=len(pattern), max_chars=SEARCH_REGEX_MAX_CHARS
            )
        )
    try:
        return regex.compile(pattern)
    except regex.error as exc:
        raise InvalidSearchRegex(agent_text.INVALID_SEARCH_REGEX.format(error=exc)) from None


def regex_filter(
    rows: Sequence[dict[str, Any]],
    pattern: str | None,
    fields: Iterable[str],
    *,
    budget_seconds: float | None = None,
) -> list[dict[str, Any]]:
    """Rows whose fields match, under one matching-time budget for the whole pass.

    Matching runs on the event loop, and ``re`` cannot be interrupted once it starts, so a
    pathological pattern would stall every session; ``regex`` checks a timeout while
    matching and an exhausted budget becomes a caller error.
    """
    if pattern is None:
        return list(rows)
    compiled = _compile_search_regex(pattern)
    fields = tuple(fields)
    budget = SEARCH_REGEX_BUDGET_SECONDS if budget_seconds is None else budget_seconds
    deadline = time.monotonic() + budget

    def text(value: Any) -> str:
        if isinstance(value, (list, tuple)):
            return " ".join(text(item) for item in value if item is not None)
        return "" if value is None else str(value)

    def budget_exhausted() -> InvalidSearchRegex:
        return InvalidSearchRegex(agent_text.SEARCH_REGEX_TOO_SLOW.format(seconds=budget))

    def search(value: Any) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise budget_exhausted()
        try:
            return compiled.search(text(value), timeout=remaining) is not None
        except TimeoutError:
            raise budget_exhausted() from None

    return [row for row in rows if any(search(row.get(field)) for field in fields)]


def lookup(
    rows: Sequence[dict[str, Any]], field: str, value: str, list_tool: str
) -> dict[str, Any]:
    matches = [row for row in rows if row.get(field) == value]
    if len(matches) > 1:
        raise ToolError(agent_text.DUPLICATE_IDENTIFIER.format(field=field, value=value))
    if not matches:
        raise CommandSelectionError(
            "not_found",
            agent_text.RESOURCE_NOT_FOUND.format(field=field, value=value),
            next_step=agent_text.IDENTIFIER_FAILURE_NEXT_STEP.format(
                argument=field, list_tool=list_tool
            ),
        )
    return matches[0]
