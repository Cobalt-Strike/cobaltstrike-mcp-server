"""Line-window reads of a task's console output, with notices outside the line offsets.

A read with nothing new for a non-terminal task waits for the beacon's next check-in when
that is near, so the common sequence is a submission and one read.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

# utc_now is read as command_lifecycle.utc_now, not imported, so tests can replace it.
from cs_server_mcp import agent_text, command_lifecycle
from cs_server_mcp.client import ClientCall
from cs_server_mcp.command_lifecycle import (
    TERMINAL_EXECUTION_STATUSES,
    CheckinForecast,
    acknowledgement_text,
    execution_status,
    get_task,
    queue_doubt,
    read_checkin_forecast,
    untouched_in_progress,
)
from cs_server_mcp.resource_views import identifier, optional_text


def _lines(text: str) -> Iterator[str]:
    # Unlike str.split, a trailing newline does not produce an empty last line.
    start = 0
    while start < len(text):
        end = text.find("\n", start)
        if end < 0:
            end = len(text)
        yield text[start:end].removesuffix("\r")
        start = end + 1


# Column order matches the header lines in agent_text.
_PS_COLUMNS = ("pid", "ppid", "process", "arch", "sessid", "user")
_LS_COLUMNS = ("type", "size", "modified", "name")
# ls reports modification time in the target's local time, month first; rendered year first.
_LS_MODIFIED_FORMAT = "%m/%d/%Y %H:%M:%S"
_LS_MODIFIED_RENDERED = "%Y-%m-%d %H:%M:%S"
# The team server cuts one long output into consecutive text entries of exactly this size
# (a 30 KB BOF report arrived as three 8,192-character entries plus a shorter last one, cut
# mid-word with no newline between). Only an entry of exactly this size is joined with the
# next; any other is a console block of its own.
_OUTPUT_CUT_SIZE = 8192


def _cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def _ls_modified(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return datetime.strptime(value.strip(), _LS_MODIFIED_FORMAT).strftime(_LS_MODIFIED_RENDERED)
    except ValueError:
        return value


def _is_table(rows: Any) -> bool:
    return isinstance(rows, list) and all(isinstance(row, Mapping) for row in rows)


def _table_lines(
    header: str, rows: Sequence[Mapping[str, Any]], columns: tuple[str, ...]
) -> Iterator[str]:
    yield header
    for row in rows:
        yield "\t".join(_cell(row.get(column)) for column in columns)


def _is_cut(text: str) -> bool:
    return _OUTPUT_CUT_SIZE in (len(text), len(text.encode("utf-8")))


def _document_lines(task: Mapping[str, Any]) -> Iterator[str]:
    for ack in task.get("taskAcknowledgements") or []:
        for line in _lines(acknowledgement_text(ack) or ""):
            yield f"[*] {line}"
    yield from _result_lines(task.get("result") or [])
    for error in task.get("error") or []:
        for line in _lines(optional_text(error.get("message")) or ""):
            yield line if line.startswith("[-]") else f"[-] {line}"


def _result_lines(outputs: Sequence[Mapping[str, Any]]) -> Iterator[str]:
    """Cut text entries are joined back before splitting; a structured entry ends a cut run."""
    cut = ""
    for output in outputs:
        kind = output.get("type")
        text = output.get("output") if kind == "text" else None
        if isinstance(text, str):
            if _is_cut(text):
                cut += text
                continue
            yield from _lines(cut + text)
            cut = ""
            continue
        if cut:
            yield from _lines(cut)
            cut = ""
        yield from _structured_lines(kind, output)
    if cut:
        yield from _lines(cut)


def _structured_lines(kind: Any, output: Mapping[str, Any]) -> Iterator[str]:
    if kind == "ps" and _is_table(output.get("processList")):
        yield from _table_lines(agent_text.OUTPUT_PS_HEADER, output["processList"], _PS_COLUMNS)
    elif kind == "ls" and _is_table(output.get("contents")):
        folder = output.get("folder")
        if isinstance(folder, str) and folder:
            yield _cell(folder)
        contents = [
            {**row, "modified": _ls_modified(row.get("modified"))} for row in output["contents"]
        ]
        yield from _table_lines(agent_text.OUTPUT_LS_HEADER, contents, _LS_COLUMNS)
    else:
        yield agent_text.OUTPUT_STRUCTURED.format(
            type=kind if kind is not None else "unknown",
            json=json.dumps(output, ensure_ascii=False, separators=(",", ":")),
        )


def _render(lines: list[str], notices: list[str], continuation: int | None) -> str:
    parts = [*lines, *notices]
    if continuation is not None:
        parts.append(agent_text.OUTPUT_CONTINUATION.format(continuation=continuation))
    return "\n".join(parts)


def _line_count(task: Mapping[str, Any]) -> int:
    return sum(1 for _ in _document_lines(task))


def _has_output(task: Mapping[str, Any]) -> bool:
    # Acknowledgements alone are the team server's, not the beacon's.
    return bool(task.get("result") or task.get("error"))


def _window_shows_output(task: Mapping[str, Any], start_line: int) -> bool:
    return _has_output(task) and _line_count(task) >= start_line


def _wait_cap(wait_seconds: float, deadline: asyncio.Timeout) -> float:
    """The configured cap, clipped so the reads after the wait keep OUTPUT_WAIT_RESERVE_SECONDS
    of the deadline."""
    when = deadline.when()
    if when is None:
        return wait_seconds
    remaining = when - asyncio.get_running_loop().time()
    return min(wait_seconds, remaining - command_lifecycle.OUTPUT_WAIT_RESERVE_SECONDS)


async def _forecast_or_never_queued(
    call_cs: ClientCall, task: Mapping[str, Any]
) -> tuple[CheckinForecast, str | None]:
    """The forecast and, when the task certainly was never queued, the note saying so."""
    forecast, beacon = await read_checkin_forecast(call_cs, identifier(task, "bid"))
    if not untouched_in_progress(task):
        return forecast, None
    doubt = await queue_doubt(call_cs, task, beacon=beacon)
    if doubt is not None and doubt.never_queued:
        return forecast, doubt.note
    return forecast, None


async def _await_output(
    call_cs: ClientCall,
    task_id: str,
    task: Mapping[str, Any],
    *,
    start_line: int,
    wait_seconds: float,
) -> tuple[Mapping[str, Any], str | None]:
    """Wait for a non-terminal task to show something new, within the cap.

    Returns the latest task and None once it has output at or past ``start_line`` or is
    terminal; otherwise the forecast or never-queued sentence for the status notice.
    """
    forecast, never_queued = await _forecast_or_never_queued(call_cs, task)
    if never_queued is not None:
        return task, never_queued
    now = command_lifecycle.utc_now()
    deadline = forecast.wait_deadline(now, cap_seconds=wait_seconds)
    if deadline is None:
        return task, forecast.text(now)
    while (remaining := (deadline - command_lifecycle.utc_now()).total_seconds()) > 0:
        await asyncio.sleep(min(command_lifecycle.OUTPUT_WAIT_POLL_SECONDS, remaining))
        task = await get_task(call_cs, task_id)
        if execution_status(task) in TERMINAL_EXECUTION_STATUSES or _window_shows_output(
            task, start_line
        ):
            return task, None
    forecast, never_queued = await _forecast_or_never_queued(call_cs, task)
    if never_queued is not None:
        return task, never_queued
    return task, forecast.text(command_lifecycle.utc_now())


async def _dead_beacon_notice(call_cs: ClientCall, task: Mapping[str, Any]) -> str | None:
    """The forecast sentence when the beacon is marked dead or unlisted; None while alive.

    A beacon cannot check in while it runs a long task, so Cobalt Strike may mark it dead
    with part of the task's output already in.
    """
    forecast, _ = await read_checkin_forecast(call_cs, identifier(task, "bid"))
    if forecast.listed and forecast.alive is not False:
        return None
    return forecast.text(command_lifecycle.utc_now())


def _size_error(max_page_chars: int, line_number: int | None = None) -> ToolError:
    subject = (
        agent_text.OUTPUT_LINE_SUBJECT.format(line_number=line_number)
        if line_number
        else agent_text.OUTPUT_NOTICES_SUBJECT
    )
    return ToolError(
        agent_text.OUTPUT_OVER_CEILING.format(subject=subject, max_page_chars=max_page_chars)
    )


@dataclass
class _Window:
    lines: list[str] = field(default_factory=list)
    observed: int = 0
    more: bool = False


def _notices(task: Mapping[str, Any], *, start_line: int, forecast: str | None) -> list[str]:
    """The bracketed notices every page repeats, since they sit outside the line offsets."""
    status = execution_status(task)
    error_count = len(task.get("error") or [])
    notices: list[str] = []
    if status != "completed" or error_count or _line_count(task) < start_line:
        shown = status or agent_text.OUTPUT_STATUS_UNKNOWN
        notices.append(
            agent_text.OUTPUT_EXECUTION_STATUS.format(status=shown)
            if forecast is None
            else agent_text.OUTPUT_EXECUTION_STATUS_FORECAST.format(status=shown, forecast=forecast)
        )
    if error_count:
        notices.append(agent_text.OUTPUT_ERRORS_REPORTED.format(count=error_count))
    return notices


async def _select_window(
    task: Mapping[str, Any],
    notices: list[str],
    *,
    start_line: int,
    max_lines: int,
    max_page_chars: int,
) -> _Window:
    """Whole lines from ``start_line``, at most ``max_lines``, under the ceiling with the notices.

    One line past a full window is read before ``more`` is set, so a page that ends at EOF
    needs no continuation notice.
    """
    window = _Window()
    for line in _document_lines(task):
        window.observed += 1
        if window.observed % 256 == 0:
            await asyncio.sleep(0)  # Lets the read deadline fire during a large document.
        if window.observed < start_line:
            continue
        if len(window.lines) == max_lines:
            window.more = True
            break
        window.lines.append(line)
        if len(_render(window.lines, notices, None)) > max_page_chars:
            if len(window.lines) == 1:
                raise _size_error(max_page_chars, window.observed)
            window.lines.pop()
            window.more = True
            break
    return window


def _page_text(window: _Window, notices: list[str], *, start_line: int, max_page_chars: int) -> str:
    if not window.lines:
        notice = (
            agent_text.OUTPUT_EMPTY
            if window.observed == 0
            else agent_text.OUTPUT_PAST_END.format(
                start_line=start_line,
                observed=window.observed,
                unit="line" if window.observed == 1 else "lines",
            )
        )
        result = _render([notice], notices, None)
        if len(result) > max_page_chars:
            raise _size_error(max_page_chars)
        return result

    # The continuation notice takes room, so a full window may lose lines to fit it.
    selected = window.lines
    while (
        window.more and len(_render(selected, notices, start_line + len(selected))) > max_page_chars
    ):
        selected.pop()
        if not selected:
            raise _size_error(max_page_chars, start_line)
    result = _render(selected, notices, start_line + len(selected) if window.more else None)
    if len(result) > max_page_chars:
        raise _size_error(max_page_chars, start_line)
    return result


async def read_command_output(
    call_cs: ClientCall,
    command_execution_id: str,
    *,
    start_line: int,
    max_lines: int,
    max_page_chars: int,
    read_timeout_seconds: float,
    wait_seconds: float = 0.0,
) -> str:
    """One line window of the task's output, waiting up to ``wait_seconds`` for a non-terminal
    task with nothing to show when the beacon's next check-in falls within that."""
    if start_line < 1 or max_lines < 1 or max_page_chars < 1 or read_timeout_seconds <= 0:
        raise ValueError(
            "start_line, max_lines, max_page_chars, and read_timeout_seconds must be positive"
        )
    if wait_seconds < 0:
        raise ValueError("wait_seconds must not be negative")

    deadline: asyncio.Timeout | None = None
    try:
        async with asyncio.timeout(read_timeout_seconds) as deadline:
            task = await get_task(call_cs, command_execution_id)
            forecast: str | None = None
            if execution_status(task) not in TERMINAL_EXECUTION_STATUSES:
                if _window_shows_output(task, start_line):
                    forecast = await _dead_beacon_notice(call_cs, task)
                else:
                    task, forecast = await _await_output(
                        call_cs,
                        command_execution_id,
                        task,
                        start_line=start_line,
                        wait_seconds=_wait_cap(wait_seconds, deadline),
                    )
            notices = _notices(task, start_line=start_line, forecast=forecast)
            window = await _select_window(
                task,
                notices,
                start_line=start_line,
                max_lines=max_lines,
                max_page_chars=max_page_chars,
            )
    except TimeoutError as exc:
        if deadline is None or not deadline.expired():
            raise
        raise ToolError(
            agent_text.OUTPUT_READ_TIMEOUT.format(read_timeout_seconds=read_timeout_seconds)
        ) from exc
    return _page_text(window, notices, start_line=start_line, max_page_chars=max_page_chars)
