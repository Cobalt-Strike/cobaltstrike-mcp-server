"""Command discovery, argument encoding, submissions, and task observations."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any, Literal, get_args

from cs_server_mcp import agent_text
from cs_server_mcp.client import ClientCall, CobaltStrikeResponseError
from cs_server_mcp.command_errors import CommandSelectionError
from cs_server_mcp.command_help import command_help, fold_subcommand_rows
from cs_server_mcp.command_policy import CommandPolicy, evaluate_command_policy
from cs_server_mcp.config import Settings
from cs_server_mcp.resource_views import (
    checkin_age_ms,
    identifier,
    identifier_sort_key,
    isoformat,
    local_page,
    optional_text,
    recent_checkin_miss,
    regex_filter,
    timestamp_key,
)
from cs_server_mcp.tool_errors import (
    UPSTREAM_ERRORS,
    InvalidArgument,
    OperationFailure,
    http_status_code,
)
from cs_server_mcp.tool_schema import ExecutionOrderField, ExecutionStatus

TERMINAL_EXECUTION_STATUSES = frozenset({"completed", "failed", "canceled"})
KNOWN_EXECUTION_STATUSES = frozenset(get_args(ExecutionStatus))
# Cobalt Strike serves its global command catalog as the help of this pseudo-beacon.
GLOBAL_CATALOG_BEACON_ID = "0"
# Catalog commands neither listed nor run. ! replays the operator's client history, which a
# REST submission has none of. clear cancels every queued task for the beacon, whoever
# queued it. file_browser and process_browser open a tab in the operator's client. The rest
# answer HTTP 400 on a live team server.
HIDDEN_COMMANDS = frozenset(
    {
        "!",
        "clear",
        "file_browser",
        "process_browser",
        "help",
        "history",
        "variables",
        "windows_error_code",
        "downloads",
        "data-store",
        "kerberos_ccache_use",
    }
)
# A live team server lists a newly accepted task about a second after answering the
# submission; receipts re-read it for this long.
NEW_TASK_GRACE_SECONDS = 2.5
NEW_TASK_POLL_SECONDS = 0.25
# A queued builtin's acknowledgement can follow the task row by a second or more (1.5 s for
# execute-assembly on a lab server). A task with nothing recorded is called never queued
# only once the beacon has checked in this long after the task was created.
ACKNOWLEDGEMENT_GRACE_SECONDS = 10.0
# How long after a due check-in the beacon's answer can take to be recorded.
CHECKIN_MARGIN_SECONDS = 3.0
OUTPUT_WAIT_POLL_SECONDS = 1.0
# Deadline left after a wait for the reads that follow it (beacon, parent, command help).
OUTPUT_WAIT_RESERVE_SECONDS = 10.0
_DIAGNOSTIC_READ_CONCURRENCY = 8
# Stated in the tool descriptions.
_STATUS_MESSAGE_MAX_CHARS = 200
_ORDER_FIELDS = frozenset(get_args(ExecutionOrderField))
# <task number in lowercase hex without leading zeros>-<decimal beacon ID>
_TASK_ID = re.compile(r"([0-9A-Fa-f]+)-([0-9]+)")


@dataclass(frozen=True)
class _ArgumentShape:
    """A builtin's console layout, verified on a live team server.

    The console splits each of the ``leading_words`` at whitespace with no quoting, then
    takes the rest of the line verbatim as the ``tail``: free text, or one literal path. The
    items after the leading words are joined with single spaces into that tail.
    """

    leading_words: int
    tail: Literal["text", "path"]


# agent_text.COMMAND_ARGUMENT_LAYOUTS names each of these layouts for the model.
_ARGUMENT_SHAPES: dict[str, _ArgumentShape] = {
    "shell": _ArgumentShape(0, "text"),
    "run": _ArgumentShape(0, "text"),
    "execute": _ArgumentShape(0, "text"),
    "powershell": _ArgumentShape(0, "text"),
    "powerpick": _ArgumentShape(0, "text"),
    "note": _ArgumentShape(0, "text"),
    "execute-assembly": _ArgumentShape(1, "text"),
    "inline-execute": _ArgumentShape(1, "text"),
    "beacon-interpreter": _ArgumentShape(1, "text"),
    "argue": _ArgumentShape(1, "text"),
    "setenv": _ArgumentShape(1, "text"),
    "runu": _ArgumentShape(1, "text"),
    "psinject": _ArgumentShape(2, "text"),
    "remote-exec": _ArgumentShape(2, "text"),
    "runas": _ArgumentShape(2, "text"),
    "spawnas": _ArgumentShape(2, "text"),
    "ls": _ArgumentShape(0, "path"),
    "cd": _ArgumentShape(0, "path"),
    "download": _ArgumentShape(0, "path"),
    "mkdir": _ArgumentShape(0, "path"),
    "rm": _ArgumentShape(0, "path"),
    "upload": _ArgumentShape(0, "path"),
    "powershell-import": _ArgumentShape(0, "path"),
    "kerberos_ticket_use": _ArgumentShape(0, "path"),
    "cancel": _ArgumentShape(0, "path"),
    "spawnto": _ArgumentShape(1, "path"),
    "dllload": _ArgumentShape(1, "path"),
}
# Deliberately absent (plain tokens only): runasadmin and inline-execute-pe, whose tails are
# unverified, and beacon-interpreter-lint, which takes a single word.

# Unlike the literal path tails above, these group double-quoted paths.
_TWO_PATH_COMMANDS = frozenset({"cp", "mv", "timestomp"})
# reg rejects quotes; queryv takes its value name after the path.
_REG_ITEM_COUNTS = {"query": 3, "queryv": 4}


def _command_catalog_call(beacon_id: str) -> str:
    if beacon_id == GLOBAL_CATALOG_BEACON_ID:
        return agent_text.COMMAND_CATALOG_CALL_GLOBAL
    return agent_text.COMMAND_CATALOG_CALL.format(beacon_id=beacon_id)


def execution_status(task: Mapping[str, Any]) -> str | None:
    status = task.get("taskStatus")
    return str(status).lower() if status is not None else None


def execution_status_message(task: Mapping[str, Any]) -> str | None:
    for error in reversed(task.get("error") or []):
        message = optional_text(error.get("message"))
        if message is not None:
            return " ".join(message.split())[:_STATUS_MESSAGE_MAX_CHARS]
    return None


def acknowledgement_text(ack: Mapping[str, Any]) -> str | None:
    # "message" is the legacy field name.
    return optional_text(ack.get("text")) or optional_text(ack.get("message"))


def _status_attention(status: str | None) -> str | None:
    """A note only for a status outside the vocabulary the tool descriptions define."""
    if status in KNOWN_EXECUTION_STATUSES:
        return None
    return agent_text.EXECUTION_STATUS_UNKNOWN.format(
        status=status or agent_text.OUTPUT_STATUS_UNKNOWN
    )


def _canonical_task_id(task_id: str) -> str:
    """The team server's own spelling: a lookup of 0FDC1-0101 answers with taskId fdc1-101, so
    asking in that spelling keeps the answer's ID equal to the request."""
    match = _TASK_ID.fullmatch(task_id)
    if match is None:
        return task_id
    return f"{int(match[1], 16):x}-{int(match[2])}"


def _task_not_found(task_id: str, *, http_status: int | None = None) -> CommandSelectionError:
    if _TASK_ID.fullmatch(task_id) is None:
        return CommandSelectionError(
            "not_found",
            agent_text.MALFORMED_TASK_NOT_FOUND.format(task_id=task_id),
            next_step=agent_text.MALFORMED_TASK_NOT_FOUND_NEXT_STEP,
            http_status=http_status,
        )
    return CommandSelectionError(
        "not_found",
        agent_text.TASK_NOT_FOUND.format(task_id=task_id),
        next_step=agent_text.TASK_NOT_FOUND_NEXT_STEP,
        http_status=http_status,
    )


def _is_record_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _validate_task(task: Mapping[str, Any], task_id: str | None = None) -> None:
    if execution_status(task) == "not_found":
        raise _task_not_found(task_id or str(task.get("taskId", "")))
    found = identifier(task, "taskId")
    if task_id is not None and found != task_id:
        raise CobaltStrikeResponseError(agent_text.TASK_ID_MISMATCH)
    identifier(task, "bid")
    for key in ("result", "error", "taskAcknowledgements"):
        if key in task and not _is_record_list(task[key]):
            raise CobaltStrikeResponseError(agent_text.INVALID_TASK_ENTRIES)


async def get_task(call_cs: ClientCall, task_id: str) -> dict[str, Any]:
    task_id = _canonical_task_id(task_id)
    try:
        task = await call_cs("get_task", task_id)
    except UPSTREAM_ERRORS as exc:
        if http_status_code(exc) == 404:
            raise _task_not_found(task_id, http_status=404) from None
        raise
    _validate_task(task, task_id)
    return task


async def read_new_task(
    call_cs: ClientCall, task_id: str, *, grace_seconds: float = NEW_TASK_GRACE_SECONDS
) -> dict[str, Any] | None:
    """Read a just-accepted task, retrying only not_found (a 404 or the 200 NOT_FOUND
    sentinel) until the grace period ends; any other failure returns None at once."""
    deadline = monotonic() + grace_seconds
    while True:
        try:
            return await get_task(call_cs, task_id)
        except CommandSelectionError as exc:
            if exc.code != "not_found":
                return None
        except UPSTREAM_ERRORS:
            return None
        remaining = deadline - monotonic()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(NEW_TASK_POLL_SECONDS, remaining))


def _execution_diagnostics(task: Mapping[str, Any]) -> dict[str, Any]:
    # Task summaries omit the arrays; a missing count is None, never zero.
    return {
        "execution_status_message": execution_status_message(task),
        "result_count": len(task["result"]) if "result" in task else None,
        "error_count": len(task["error"]) if "error" in task else None,
    }


def _command_line(task: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The command token and the rest of the recorded console line, kept verbatim: parsing it
    as a shell command would corrupt console syntax."""
    command_line = task.get("taskCommand")
    if not isinstance(command_line, str) or not command_line.strip():
        return None, None
    name, *rest = re.split(r"\s", command_line.lstrip(), maxsplit=1)
    return name, rest[0] if rest else ""


def _execution_row(task: Mapping[str, Any]) -> dict[str, Any]:
    _validate_task(task)
    command_name, command_arguments = _command_line(task)
    return {
        "command_execution_id": identifier(task, "taskId"),
        "execution_status": execution_status(task),
        **_execution_diagnostics(task),
        "command_name": command_name,
        "command_arguments": command_arguments,
        "beacon_id": identifier(task, "bid"),
        "requested_by": task.get("user"),
        "submitted_at": isoformat(task.get("created")),
        "updated_at": isoformat(task.get("updated")),
        "job_id": str(task["jid"]) if task.get("jid") is not None else None,
    }


def present_execution_observation(task: Mapping[str, Any]) -> dict[str, Any]:
    row = _execution_row(task)
    errors = task.get("error") or []
    last_error = optional_text(errors[-1].get("message")) if errors else None
    return {
        **row,
        "execution_status_note": _status_attention(execution_status(task)),
        "last_error_message": (
            last_error[:_STATUS_MESSAGE_MAX_CHARS] if last_error is not None else None
        ),
        "tactics": task.get("tactics") or [],
        # No timestamp: the team server stamps an acknowledgement with the time it is read.
        "acknowledgements": [
            {"text": acknowledgement_text(ack), "tactics": ack.get("tactics") or []}
            for ack in task.get("taskAcknowledgements") or []
        ],
    }


def untouched_in_progress(task: Mapping[str, Any]) -> bool:
    """In progress with no acknowledgement, output, or error: what a task Cobalt Strike
    created and never queued looks like for good. Only a detail record answers this; task
    summaries omit the arrays."""
    return execution_status(task) == "in_progress" and not any(
        task.get(key) for key in ("taskAcknowledgements", "result", "error")
    )


async def reread_untouched_task(
    call_cs: ClientCall,
    task_id: str,
    task: Mapping[str, Any],
    *,
    grace_seconds: float = NEW_TASK_GRACE_SECONDS,
) -> Mapping[str, Any]:
    """Re-read an untouched task while its acknowledgement may still land."""
    latest = task
    deadline = monotonic() + grace_seconds
    while untouched_in_progress(latest):
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(NEW_TASK_POLL_SECONDS, remaining))
        latest = await read_new_task(call_cs, task_id, grace_seconds=0) or latest
    return latest


@dataclass(frozen=True)
class QueueDoubt:
    never_queued: bool
    note: str


def _checked_in_after_grace(last_seen_at: str | None, created_at: str | None) -> bool:
    if not last_seen_at or not created_at:
        return False
    grace = timedelta(seconds=ACKNOWLEDGEMENT_GRACE_SECONDS)
    return timestamp_key(last_seen_at) > timestamp_key(created_at) + grace


async def queue_doubt(
    call_cs: ClientCall, task: Mapping[str, Any], *, beacon: Mapping[str, Any] | None = None
) -> QueueDoubt | None:
    """Whether Cobalt Strike may never have queued this task; None when there is no doubt.

    A queued builtin carries an acknowledgement within seconds, so an untouched builtin task
    is certainly never queued once the beacon has checked in ACKNOWLEDGEMENT_GRACE_SECONDS
    after the task was created, and merely unacknowledged before. A user-defined command can
    run without an acknowledgement, so it earns a doubt only after such a check-in.
    """
    if not untouched_in_progress(task):
        return None
    command_name, _ = _command_line(task)
    if command_name is None:
        return None
    beacon_id = identifier(task, "bid")
    try:
        command = await call_cs("get_beacon_command", beacon_id, command_name)
    except (*UPSTREAM_ERRORS, CommandSelectionError):
        command = None
    builtin = isinstance(command, Mapping) and "builtin" in (command.get("groups") or [])
    if beacon is None:
        try:
            beacon = await call_cs("get_beacon", beacon_id)
        except UPSTREAM_ERRORS:
            beacon = None
    last_seen_at = isoformat(beacon.get("lastCheckinTime")) if beacon is not None else None
    answered = _checked_in_after_grace(last_seen_at, isoformat(task.get("created")))
    if builtin:
        if answered:
            return QueueDoubt(
                never_queued=True,
                note=agent_text.EXECUTION_NEVER_QUEUED.format(
                    last_seen_at=last_seen_at, beacon_id=beacon_id, command_name=command_name
                ),
            )
        return QueueDoubt(never_queued=False, note=agent_text.EXECUTION_UNACKNOWLEDGED)
    if not answered:
        return None
    return QueueDoubt(
        never_queued=False,
        note=agent_text.EXECUTION_UNANSWERED.format(
            last_seen_at=last_seen_at, beacon_id=beacon_id, command_name=command_name
        ),
    )


async def observe_execution(call_cs: ClientCall, task: Mapping[str, Any]) -> dict[str, Any]:
    observation = present_execution_observation(task)
    doubt = await queue_doubt(call_cs, task)
    if doubt is not None:
        observation["execution_status_note"] = doubt.note
    return observation


def _sleep_seconds(beacon: Mapping[str, Any]) -> float | None:
    sleep = beacon.get("sleep")
    if not isinstance(sleep, Mapping):
        return None
    value = sleep.get("sleep")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def _dead_beacon_warning(
    beacon_id: str,
    *,
    age: str | None,
    checkin_ms: int | None,
    recent: str,
    lost: str,
) -> str:
    template = recent if recent_checkin_miss(checkin_ms) else lost
    return template.format(
        beacon_id=beacon_id,
        age=agent_text.RECEIPT_BEACON_DEAD_AGE.format(age=age) if age else "",
    )


@dataclass(frozen=True)
class CheckinForecast:
    """When a beacon is next expected to check in.

    Jitter only shortens a sleep, so one sleep after the last check-in bounds the next. A
    linked beacon is polled at its parent's sleep, so ``last_seen_at`` and ``sleep_seconds``
    are the parent's for one; ``alive`` and ``last_checkin_ms`` stay its own.
    """

    beacon_id: str
    alive: bool | None = None
    last_seen_at: str | None = None
    last_checkin_age: str | None = None
    sleep_seconds: float | None = None
    last_checkin_ms: int | None = None
    # False when Cobalt Strike answered 404: the beacon was removed.
    listed: bool = True

    @property
    def due_at(self) -> datetime | None:
        if self.last_seen_at is None or self.sleep_seconds is None:
            return None
        return timestamp_key(self.last_seen_at) + timedelta(seconds=self.sleep_seconds)

    def wait_deadline(self, now: datetime, *, cap_seconds: float) -> datetime | None:
        """When a read waiting for the beacon's answer gives up, or None not to wait at all.

        Only a listed beacon marked alive with a known check-in inside the cap is waited
        for. A check-in already due may have happened without the record saying so yet (a
        lab server lagged one that coincided with a submission), so that case waits one more
        sleep; a beacon more than a sleep late is overdue, and the overdue notice is the answer.
        """
        due = self.due_at
        if cap_seconds <= 0 or not self.listed or self.alive is False or due is None:
            return None
        assert self.sleep_seconds is not None
        if now > due + timedelta(seconds=max(self.sleep_seconds, CHECKIN_MARGIN_SECONDS)):
            return None
        expected = due if due >= now else now + timedelta(seconds=self.sleep_seconds)
        deadline = expected + timedelta(seconds=CHECKIN_MARGIN_SECONDS)
        if deadline - now > timedelta(seconds=cap_seconds):
            return None
        return deadline

    def text(self, now: datetime) -> str:
        if not self.listed:
            return agent_text.OUTPUT_BEACON_UNLISTED.format(beacon_id=self.beacon_id)
        if self.alive is False:
            return _dead_beacon_warning(
                self.beacon_id,
                age=self.last_checkin_age,
                checkin_ms=self.last_checkin_ms,
                recent=agent_text.OUTPUT_BEACON_DEAD_RECENT,
                lost=agent_text.OUTPUT_BEACON_DEAD,
            )
        due = self.due_at
        if due is None:
            return agent_text.OUTPUT_CHECKIN_UNKNOWN.format(beacon_id=self.beacon_id)
        if now >= due:
            return agent_text.OUTPUT_BEACON_LATE.format(
                last_seen_at=self.last_seen_at,
                sleep_seconds=self.sleep_seconds,
                beacon_id=self.beacon_id,
            )
        return agent_text.OUTPUT_NEXT_CHECKIN.format(
            expected_at=isoformat(due),
            sleep_seconds=self.sleep_seconds,
            last_seen_at=self.last_seen_at,
        )


async def read_checkin_forecast(
    call_cs: ClientCall, beacon_id: str
) -> tuple[CheckinForecast, Mapping[str, Any] | None]:
    """The forecast and the beacon record it was read from, so a caller needing both reads
    the beacon once."""
    try:
        beacon = await call_cs("get_beacon", beacon_id)
    except UPSTREAM_ERRORS as exc:
        listed = http_status_code(exc) != 404
        return CheckinForecast(beacon_id=beacon_id, listed=listed), None
    alive = beacon.get("alive")
    timing: Mapping[str, Any] | None = beacon
    parent_id = beacon.get("pbid")
    if parent_id:
        try:
            timing = await call_cs("get_beacon", str(parent_id))
        except UPSTREAM_ERRORS:
            timing = None
    forecast = CheckinForecast(
        beacon_id=beacon_id,
        alive=alive if isinstance(alive, bool) else None,
        last_checkin_age=optional_text(beacon.get("lastCheckinFormatted")),
        last_seen_at=isoformat(timing.get("lastCheckinTime")) if timing is not None else None,
        sleep_seconds=_sleep_seconds(timing) if timing is not None else None,
        last_checkin_ms=checkin_age_ms(beacon),
    )
    return forecast, beacon


def utc_now() -> datetime:
    # Tests replace this and ``monotonic`` with a virtual clock.
    return datetime.now(UTC)


def present_execution_list(
    tasks: Sequence[Mapping[str, Any]],
    *,
    settings: Settings,
    limit: int | None = None,
    offset: int | None = None,
    search_regex: str | None = None,
    status: str | None = None,
    since: datetime | None = None,
    order_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    order = _validated_order(order_by)
    rows = [_execution_row(task) for task in tasks if execution_status(task) != "not_found"]
    if status is not None:
        rows = [row for row in rows if row["execution_status"] == status]
    if since is not None:
        rows = [
            row
            for row in rows
            if row["submitted_at"] and datetime.fromisoformat(row["submitted_at"]) >= since
        ]
    rows = regex_filter(rows, search_regex, agent_text.EXECUTION_SEARCH_FIELDS)
    _sort_executions(rows, order)
    page = local_page(
        rows, limit=limit, offset=offset, resource="command_executions", settings=settings
    )
    # Filled by enrich_execution_diagnostics when a detail read fails.
    return {**page, "execution_status_note": None}


def _validated_order(order_by: Sequence[str] | None) -> list[str]:
    """Newest first by default, with the ID appended as the tie-breaker."""
    order = list(order_by) if order_by else ["-submitted_at", "-id"]
    unsupported = next((key for key in order if key not in _ORDER_FIELDS), None)
    if unsupported is not None:
        raise InvalidArgument(
            agent_text.EXECUTION_ORDER_BY_UNSUPPORTED.format(
                item=unsupported, allowed=sorted(_ORDER_FIELDS)
            )
        )
    if len({key.lstrip("-") for key in order}) != len(order):
        raise InvalidArgument(agent_text.EXECUTION_ORDER_BY_DUPLICATE)
    if not any(key.lstrip("-") == "id" for key in order):
        order.append("-id" if order[0].startswith("-") else "id")
    return order


def _sort_executions(rows: list[dict[str, Any]], order: Sequence[str]) -> None:
    for key in reversed(order):
        rows.sort(key=_execution_sort_key(key.lstrip("-")), reverse=key.startswith("-"))


def _execution_sort_key(field: str) -> Callable[[Mapping[str, Any]], Any]:
    if field == "id":
        return lambda row: identifier_sort_key(row["command_execution_id"])
    return lambda row: timestamp_key(row[field])


async def enrich_execution_diagnostics(
    call_cs: ClientCall, page: dict[str, Any], *, timeout_seconds: float
) -> dict[str, Any]:
    """Read detail counts for the rows of this page whose summary lacked them."""
    semaphore = asyncio.Semaphore(_DIAGNOSTIC_READ_CONCURRENCY)

    async def enrich(row: dict[str, Any]) -> None:
        if row["result_count"] is not None and row["error_count"] is not None:
            return
        try:
            async with semaphore:
                detail = await get_task(call_cs, row["command_execution_id"])
        except (*UPSTREAM_ERRORS, CommandSelectionError):
            return
        if identifier(detail, "bid") != row["beacon_id"]:
            return
        row.update(_execution_diagnostics(detail))

    deadline = None
    try:
        async with asyncio.timeout(timeout_seconds) as deadline:
            await asyncio.gather(*(enrich(row) for row in page["results"]))
    except TimeoutError:
        if deadline is None or not deadline.expired():
            raise
    if any(row["error_count"] is None or row["result_count"] is None for row in page["results"]):
        page["execution_status_note"] = agent_text.EXECUTION_DIAGNOSTICS_UNAVAILABLE
    return page


def _unsupported_command(command_name: str, beacon_id: str) -> CommandSelectionError:
    scope = (
        agent_text.SCOPE_GLOBAL_CATALOG
        if beacon_id == GLOBAL_CATALOG_BEACON_ID
        else agent_text.SCOPE_BEACON.format(beacon_id=beacon_id)
    )
    return CommandSelectionError(
        "unsupported_command",
        agent_text.COMMAND_UNAVAILABLE.format(command_name=command_name, scope=scope),
        next_step=agent_text.FIND_AVAILABLE_COMMAND_NEXT_STEP.format(
            catalog_call=_command_catalog_call(beacon_id)
        ),
    )


def _help_unavailable(
    beacon_id: str, beacon: Mapping[str, Any], command_name: str | None = None
) -> CommandSelectionError:
    alive = beacon.get("alive")
    message = agent_text.HELP_UNAVAILABLE.format(
        beacon_id=beacon_id, alive=str(alive).lower() if isinstance(alive, bool) else "unknown"
    )
    if command_name is not None:
        message += agent_text.HELP_UNAVAILABLE_COMMAND.format(command_name=command_name)
    return CommandSelectionError(
        "help_unavailable",
        message,
        next_step=agent_text.HELP_UNAVAILABLE_NEXT_STEP.format(beacon_id=beacon_id),
    )


def _is_hidden(row: Any) -> bool:
    return isinstance(row, Mapping) and row.get("name") in HIDDEN_COMMANDS


async def list_commands(
    call_cs: ClientCall, beacon_id: str, *, command_name: str | None = None
) -> list[dict[str, Any]]:
    try:
        catalog = await call_cs("list_beacon_commands", beacon_id)
    except UPSTREAM_ERRORS as exc:
        if http_status_code(exc) != 404:
            raise
        catalog = []
    if catalog:
        return [row for row in fold_subcommand_rows(catalog) if not _is_hidden(row)]
    # No catalog for an existing beacon means help is unavailable (a dead beacon may cause
    # that); a missing beacon surfaces as not_found from this lookup instead.
    beacon = await call_cs("get_beacon", beacon_id)
    raise _help_unavailable(beacon_id, beacon, command_name)


def _policy_denies(policy: CommandPolicy, command: Mapping[str, Any]) -> bool:
    name = command.get("name")
    if not isinstance(name, str):
        return False
    decision = evaluate_command_policy(
        policy, command_name=name, groups=command.get("groups") or []
    )
    return decision.outcome == "deny"


def present_command_catalog(
    rows: Sequence[Mapping[str, Any]],
    *,
    include_help: bool,
    search_regex: str | None,
    limit: int | None,
    offset: int | None,
    settings: Settings,
    policy: CommandPolicy,
) -> dict[str, Any]:
    """Denied commands are left out. The search runs over the presented fields, help included,
    before the page is cut and before help is dropped from rows not asked for it."""
    catalog = [
        {
            "command_name": identifier(row, "name"),
            "description": row.get("description"),
            "help": command_help(row),
        }
        for row in rows
        if not _policy_denies(policy, row)
    ]
    catalog = regex_filter(catalog, search_regex, agent_text.COMMAND_SEARCH_FIELDS)
    catalog.sort(key=lambda row: row["command_name"])
    if not include_help:
        catalog = [{key: value for key, value in row.items() if key != "help"} for row in catalog]
    return local_page(catalog, limit=limit, offset=offset, resource="commands", settings=settings)


def serialize_command_arguments(arguments: Sequence[str], *, command: Mapping[str, Any]) -> str:
    """Encode items only where the console parser is known: verified builtin layouts, and
    user-defined commands, whose line is split at whitespace with double quotes grouping.
    Other commands accept plain tokens only; guessing their quoting could change a value."""
    name = command["name"]
    groups = command.get("groups") or []
    if "builtin" in groups:
        encoded = _verified_builtin_arguments(arguments, name)
        if encoded is not None:
            return encoded
    elif "userdefined" in groups:
        return " ".join(_script_argument(value, name) for value in arguments)
    return " ".join(_plain_argument(value, name) for value in arguments)


def _verified_builtin_arguments(arguments: Sequence[str], name: str) -> str | None:
    if name in _ARGUMENT_SHAPES:
        return _shaped_arguments(arguments, name, _ARGUMENT_SHAPES[name])
    if name in _TWO_PATH_COMMANDS:
        return _two_path_arguments(arguments, name)
    if name == "reg" and arguments and arguments[0] in _REG_ITEM_COUNTS:
        return _reg_query_arguments(arguments, name)
    return None


def _two_path_arguments(arguments: Sequence[str], name: str) -> str:
    if len(arguments) != 2:
        raise _layout_error(name)
    return " ".join(_quoted_path(value, name) for value in arguments)


def _reg_query_arguments(arguments: Sequence[str], name: str) -> str:
    if len(arguments) != _REG_ITEM_COUNTS[arguments[0]]:
        raise _layout_error(name)
    subcommand, arch, path, *value_name = arguments
    encoded = [_word(subcommand, name), _word(arch, name), _literal_path(path, name)]
    return " ".join(encoded + [_word(value, name) for value in value_name])


def _shaped_arguments(arguments: Sequence[str], name: str, shape: _ArgumentShape) -> str:
    encoded = [_word(value, name) for value in arguments[: shape.leading_words]]
    tail = arguments[shape.leading_words :]
    if not tail:
        return " ".join(encoded)
    # An empty item among several would vanish into a doubled space.
    if len(tail) > 1 and any(not item for item in tail):
        raise InvalidArgument(agent_text.COMMAND_ARGUMENTS_EMPTY.format(command_name=name))
    value = " ".join(tail)
    if shape.tail == "path":
        encoded.append(_literal_path(value, name))
    elif shape.leading_words and not value:
        raise InvalidArgument(agent_text.COMMAND_ARGUMENTS_EMPTY.format(command_name=name))
    else:
        encoded.append(_raw_text(value, name))
    return " ".join(encoded)


def _layout_error(command_name: str) -> InvalidArgument:
    return InvalidArgument(
        agent_text.COMMAND_ARGUMENTS_LAYOUT.format(
            command_name=command_name, layout=agent_text.COMMAND_ARGUMENT_LAYOUTS[command_name]
        )
    )


def _has_control(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _is_word(value: str) -> bool:
    return (
        bool(value)
        and not _has_control(value)
        and not any(char.isspace() or char in "'\"" for char in value)
    )


def _raw_text(value: str, command_name: str) -> str:
    if "\x00" in value:
        raise InvalidArgument(agent_text.COMMAND_ARGUMENTS_NUL.format(command_name=command_name))
    return value


def _word(value: str, command_name: str) -> str:
    if not _is_word(value):
        raise InvalidArgument(
            agent_text.COMMAND_ARGUMENTS_WORD.format(
                command_name=command_name,
                layout=agent_text.COMMAND_ARGUMENT_LAYOUTS[command_name],
            )
        )
    return value


def _plain_argument(value: str, command_name: str) -> str:
    if not _is_word(value):
        raise InvalidArgument(
            agent_text.COMMAND_ARGUMENTS_PLAIN_ONLY.format(command_name=command_name)
        )
    return value


def _script_argument(value: str, command_name: str) -> str:
    """Double-quoted when the console would otherwise split it.

    Verified live: ``dir "C:\\Program Files"`` arrives as one value, the unquoted form as
    two, and an empty item sent as "" reaches a BOF as an empty argument. An embedded double
    quote has no escape, so it is refused.
    """
    if '"' in value or _has_control(value):
        raise InvalidArgument(
            agent_text.COMMAND_ARGUMENTS_SCRIPT_UNSAFE.format(command_name=command_name)
        )
    if not value or any(char.isspace() or char == "'" for char in value):
        return f'"{value}"'
    return value


def _literal_path(value: str, command_name: str) -> str:
    if not value or value != value.strip() or '"' in value or _has_control(value):
        raise InvalidArgument(
            agent_text.COMMAND_ARGUMENTS_UNSAFE_PATH.format(command_name=command_name)
        )
    return value


def _quoted_path(value: str, command_name: str) -> str:
    if not value or '"' in value or _has_control(value):
        raise InvalidArgument(
            agent_text.COMMAND_ARGUMENTS_UNSAFE_PATH.format(command_name=command_name)
        )
    return f'"{value}"' if any(char.isspace() or char == "'" for char in value) else value


def validate_command_request(*, command_name: str) -> None:
    if (
        command_name in {"", ".", ".."}
        or any(char.isspace() for char in command_name)
        or _has_control(command_name)
    ):
        raise InvalidArgument(agent_text.COMMAND_NAME_INVALID)


def _command_key(name: str) -> str:
    return name.casefold()


async def select_command(call_cs: ClientCall, beacon_id: str, command_name: str) -> dict[str, Any]:
    """The exact help row, else the one catalog row matching in another letter case."""
    if command_name in HIDDEN_COMMANDS:
        raise _unsupported_command(command_name, beacon_id)
    try:
        command = await call_cs("get_beacon_command", beacon_id, command_name)
    except UPSTREAM_ERRORS as exc:
        if http_status_code(exc) != 404:
            raise
        command = None
    if command is None:
        # Help answers 404 for a missing beacon, an unknown command, a name in another
        # letter case, and possibly a beacon without help; the catalog settles which.
        catalog = await list_commands(call_cs, beacon_id, command_name=command_name)
        return _catalog_command(catalog, beacon_id, command_name)
    if command.get("name") != command_name:
        raise _unsupported_command(command_name, beacon_id)
    return command


def _catalog_command(catalog: Sequence[Any], beacon_id: str, command_name: str) -> dict[str, Any]:
    for row in catalog:
        if isinstance(row, Mapping) and row.get("name") == command_name:
            return row
    matches = [
        row
        for row in catalog
        if isinstance(row, Mapping)
        and isinstance(row.get("name"), str)
        and _command_key(row["name"]) == _command_key(command_name)
    ]
    if len(matches) > 1:
        raise CommandSelectionError(
            "ambiguous_command",
            agent_text.COMMAND_AMBIGUOUS.format(command_name=command_name),
            next_step=agent_text.COMMAND_AMBIGUOUS_NEXT_STEP.format(
                catalog_call=_command_catalog_call(beacon_id)
            ),
        )
    if not matches:
        raise _unsupported_command(command_name, beacon_id)
    return matches[0]


def _receipt_note(
    task: Mapping[str, Any] | None,
    *,
    beacon_id: str,
    builtin: bool,
    beacon: Mapping[str, Any] | None,
) -> str | None:
    """None when nothing needs attention. Seconds after submission an untouched builtin task
    cannot be told from one never queued, so the receipt only says it is unacknowledged. A
    dead beacon's warning leads whatever else the note says."""
    if task is None:
        note = agent_text.RECEIPT_STATUS_UNAVAILABLE
    elif builtin and untouched_in_progress(task):
        note = agent_text.EXECUTION_UNACKNOWLEDGED
    else:
        note = _status_attention(execution_status(task))
    if beacon is None or beacon.get("alive") is not False:
        return note
    warning = _dead_beacon_warning(
        beacon_id,
        age=optional_text(beacon.get("lastCheckinFormatted")),
        checkin_ms=checkin_age_ms(beacon),
        recent=agent_text.RECEIPT_BEACON_DEAD_RECENT,
        lost=agent_text.RECEIPT_BEACON_DEAD,
    )
    return warning if note is None else f"{warning} {note}"


def build_receipt(
    submitted: Mapping[str, Any],
    *,
    beacon_id: str,
    command_name: str,
    arguments: str | None,
    submitted_arguments: Sequence[str],
    task: Mapping[str, Any] | None = None,
    builtin: bool = False,
    beacon: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A submission answered without a task ID ran nothing and is raised as a rejection."""
    task_id = submitted.get("taskId")
    if not isinstance(task_id, str) or not task_id:
        raise OperationFailure(
            CommandSelectionError(
                "no_task_created",
                agent_text.NO_TASK_CREATED.format(
                    status=submitted.get("status"), message=submitted.get("message")
                ),
                next_step=agent_text.NO_TASK_CREATED_NEXT_STEP,
            ),
            leading={"submission_outcome": "rejected"},
        )
    return {
        "submission_outcome": "accepted",
        "command_execution_id": task_id,
        "beacon_id": beacon_id,
        "command_name": command_name,
        "command_arguments": arguments,
        "submitted_arguments": list(submitted_arguments),
        "execution_status": execution_status(task) if task is not None else None,
        "execution_status_message": execution_status_message(task) if task is not None else None,
        "execution_status_note": _receipt_note(
            task, beacon_id=beacon_id, builtin=builtin, beacon=beacon
        ),
        "submitted_at": isoformat(task.get("created")) if task is not None else None,
    }


def submission_failure(exc: BaseException) -> OperationFailure:
    """A 4xx means nothing ran; anything else leaves the outcome uncertain."""
    status = http_status_code(exc)
    rejected = status is not None and 400 <= status < 500
    return OperationFailure(
        exc,
        leading={"submission_outcome": "rejected" if rejected else "uncertain"},
        next_step=(
            f"{agent_text.SUBMISSION_REJECTED_NEXT_STEP} {agent_text.SUBMISSION_REJECTED_HISTORY_NOTE}"
            if rejected
            else agent_text.SUBMISSION_UNCERTAIN_NEXT_STEP
        ),
    )
