"""The error envelope every failed tool call carries.

Four kinds of failure take it: ``CommandSelectionError`` (policy, selection, local
lookups), input-schema rejections (reported by ``tool_schema.ClosedTool``),
``InvalidArgument`` (rules the schema cannot express), and expected Cobalt Strike failures
(HTTP errors, unreadable responses, transport faults). ``OperationFailure`` wraps one that
followed a state-changing request so the envelope leads with the state it left. Any other
exception is an implementation error and stays a crash, so its text never reaches the model.
"""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping
from http import HTTPStatus
from typing import Any

import aiohttp
import pydantic_core
from cs_sdk_python.api_client.exceptions import ApiException, OpenApiException
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from cs_server_mcp import agent_text
from cs_server_mcp.client import CobaltStrikeResponseError
from cs_server_mcp.command_errors import CommandSelectionError

# SDK errors (HTTP error responses included), unreadable responses, and the aiohttp
# transport faults the SDK does not wrap.
UPSTREAM_ERRORS: tuple[type[BaseException], ...] = (
    OpenApiException,
    CobaltStrikeResponseError,
    aiohttp.ClientError,
    TimeoutError,
)

_IDENTIFIER_LIST_TOOLS = {
    "command_execution_id": "cs_list_command_executions",
    "artifact_reference": "cs_list_artifacts",
    "download_id": "cs_list_downloads",
    "screenshot_id": "cs_list_screenshots",
    "beacon_id": "cs_list_beacons",
}
_CONTEXT_VALUE_CHARS = 200
_ERROR_MESSAGE_MAX_CHARS = 200
_ERROR_CODE_BY_HTTP_STATUS = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "invalid_request",
    429: "rate_limited",
}


class InvalidArgument(ValueError):
    """An argument the schema accepts but the request cannot use. The message reaches the model."""

    code = "invalid_argument"

    def __init__(self, message: str, *, next_step: str | None = None) -> None:
        super().__init__(message)
        self.next_step = next_step or agent_text.CORRECT_REQUEST_NEXT_STEP


class InvalidSearchRegex(InvalidArgument):
    """Invalid, too long, or too slow. Reported as invalid_request like a server-side search
    rejection, but with no HTTP status since the pattern never left this server."""

    code = "invalid_request"

    def __init__(self, message: str, *, next_step: str | None = None) -> None:
        super().__init__(message, next_step=next_step or agent_text.SEARCH_VALIDATION_NEXT_STEP)


class OperationFailure(Exception):
    """A failure after a state-changing request; ``leading`` opens the envelope with the state
    it left. The exception text names only the cause's type."""

    def __init__(
        self,
        cause: BaseException,
        *,
        leading: Mapping[str, Any],
        next_step: str | None = None,
    ) -> None:
        super().__init__(type(cause).__name__)
        self.cause = cause
        self.leading = dict(leading)
        self.next_step = next_step


_REPORTED_ERRORS: tuple[type[BaseException], ...] = (
    InvalidArgument,
    CommandSelectionError,
    *UPSTREAM_ERRORS,
)


def error_result(payload: Mapping[str, Any]) -> CallToolResult:
    """The same payload as text and as ``structuredContent``; neither side validates an error."""
    rendered = pydantic_core.to_json(payload, fallback=str, indent=2)
    return CallToolResult(
        content=[TextContent(type="text", text=rendered.decode())],
        structured_content=pydantic_core.from_json(rendered),
        is_error=True,
    )


def error_envelope(
    *,
    code: str,
    message: str,
    http_status: int | None,
    tool: str,
    arguments: Mapping[str, Any],
    next_step: str,
    leading: Mapping[str, Any] | None = None,
    rule: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message, "http_status": http_status}
    if rule is not None:
        error["rule"] = rule
    return {
        **(leading or {}),
        "error": error,
        "tool": tool,
        **_bounded_request(arguments),
        "next_step": next_step,
    }


def http_status_code(exc: BaseException) -> int | None:
    value = getattr(exc, "status", getattr(exc, "status_code", None))
    return value if isinstance(value, int) and value > 0 else None


def _bounded_line(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= _ERROR_MESSAGE_MAX_CHARS:
        return collapsed
    return collapsed[:_ERROR_MESSAGE_MAX_CHARS] + "..."


def upstream_error_detail(exc: BaseException) -> str | None:
    if not isinstance(exc, ApiException) or not isinstance(exc.body, str) or not exc.body.strip():
        return None
    try:
        data = json.loads(exc.body)
    except ValueError:
        return exc.body
    if isinstance(data, dict):
        for key in ("message", "detail", "error"):
            if isinstance(data.get(key), str) and data[key].strip():
                return data[key]
    return exc.body


def _failure_detail(exc: BaseException) -> str:
    status = http_status_code(exc)
    if status is None:
        if isinstance(exc, CobaltStrikeResponseError):
            return _bounded_line(str(exc)) or type(exc).__name__
        return type(exc).__name__
    message = agent_text.HTTP_FAILURE.format(status=status)
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = ""
    if reason:
        message += agent_text.HTTP_FAILURE_REASON.format(reason=reason)
    detail = upstream_error_detail(exc)
    if detail:
        message += agent_text.HTTP_FAILURE_DETAIL.format(detail=_bounded_line(detail))
    return message


def _next_step(status: int | None) -> str:
    if status is not None and status in agent_text.NEXT_STEP_BY_HTTP_STATUS:
        return agent_text.NEXT_STEP_BY_HTTP_STATUS[status]
    if status is not None and 400 <= status < 500:
        return agent_text.CORRECT_REQUEST_NEXT_STEP
    return agent_text.UNCERTAIN_NEXT_STEP


def _sdk_refused_request(exc: BaseException) -> bool:
    """The SDK refused to build the request, so nothing reached the team server."""
    return (
        isinstance(exc, OpenApiException)
        and not isinstance(exc, ApiException)
        and http_status_code(exc) is None
    )


def _default_next_step(exc: BaseException) -> str:
    if _sdk_refused_request(exc):
        return agent_text.CORRECT_REQUEST_NEXT_STEP
    if isinstance(exc, CobaltStrikeResponseError):
        return agent_text.CS_RESPONSE_UNREADABLE_NEXT_STEP
    return _next_step(http_status_code(exc))


def upstream_failure_message(exc: BaseException) -> str:
    """Transport faults name only their type, so connection details stay on the server."""
    if http_status_code(exc) is not None or isinstance(
        exc, OpenApiException | CobaltStrikeResponseError
    ):
        return agent_text.CS_REQUEST_FAILED.format(detail=_failure_detail(exc))
    return agent_text.CS_NO_ANSWER.format(exception=type(exc).__name__)


def _request_context(arguments: Mapping[str, Any]) -> dict[str, Any]:
    # An allowlist: command arguments and the Context never reach the envelope. A detail
    # selector wins over filters, since the list tools ignore filters beside one.
    for name in _IDENTIFIER_LIST_TOOLS:
        if name != "beacon_id" and arguments.get(name) is not None:
            return {name: arguments[name]}
    return {
        name: arguments[name]
        for name in ("beacon_id", "command_name", "search_regex")
        if arguments.get(name) is not None
    }


def _bounded_request(arguments: Mapping[str, Any]) -> dict[str, Any]:
    request = _request_context(arguments)
    truncated: list[str] = []
    for name, value in request.items():
        if isinstance(value, str) and len(value) > _CONTEXT_VALUE_CHARS:
            request[name] = value[:_CONTEXT_VALUE_CHARS]
            truncated.append(name)
    return {"request": request, "truncated_arguments": truncated}


def _upstream_error_code(exc: BaseException, status: int | None) -> str:
    if _sdk_refused_request(exc):
        return "invalid_request"
    if status is not None or isinstance(exc, ApiException | CobaltStrikeResponseError):
        return _ERROR_CODE_BY_HTTP_STATUS.get(status, "upstream_error")
    return "transport_error"


def _identifier_next_steps(request: Mapping[str, Any]) -> str:
    return " ".join(
        agent_text.IDENTIFIER_FAILURE_NEXT_STEP.format(argument=name, list_tool=list_tool)
        for name, list_tool in _IDENTIFIER_LIST_TOOLS.items()
        if name in request
    )


def _not_found_detail(request: Mapping[str, Any]) -> str:
    missing = next((name for name in _IDENTIFIER_LIST_TOOLS if name in request), None)
    if missing is None:
        return ""
    return agent_text.HTTP_FAILURE_DETAIL.format(
        detail=agent_text.NOT_FOUND_WITHOUT_DETAIL.format(
            argument=missing, value=_bounded_line(str(request[missing]))
        )
    )


def upstream_error_result(
    exc: BaseException,
    *,
    tool: str,
    arguments: Mapping[str, Any],
    next_step: str | None = None,
    error_fields: Mapping[str, Any] | None = None,
) -> CallToolResult:
    """The next step follows the HTTP status unless the caller names one; a request the SDK
    refused to build is always the model's to correct."""
    status = http_status_code(exc)
    request = _request_context(arguments)
    if _sdk_refused_request(exc):
        next_step = agent_text.CORRECT_REQUEST_NEXT_STEP
    else:
        next_step = next_step or _default_next_step(exc)
        if status in (400, 404, 422) and (identifier_steps := _identifier_next_steps(request)):
            next_step += " " + identifier_steps
    message = upstream_failure_message(exc)
    if status == 404 and upstream_error_detail(exc) is None:
        # A live team server sends no body for most 404s.
        message += _not_found_detail(request)
    return error_result(
        error_envelope(
            code=_upstream_error_code(exc, status),
            message=message,
            http_status=status,
            tool=tool,
            arguments=arguments,
            next_step=next_step,
            leading=error_fields,
        )
    )


def _failure_result(
    exc: BaseException,
    *,
    tool: str,
    arguments: Mapping[str, Any],
    leading: Mapping[str, Any] | None,
    next_step: str | None = None,
) -> CallToolResult:
    if isinstance(exc, InvalidArgument):
        return error_result(
            error_envelope(
                code=exc.code,
                message=str(exc),
                http_status=None,
                tool=tool,
                arguments=arguments,
                next_step=next_step or exc.next_step,
                leading=leading,
            )
        )
    if isinstance(exc, CommandSelectionError):
        return error_result(
            error_envelope(
                code=exc.code,
                message=exc.message,
                http_status=exc.http_status,
                tool=tool,
                arguments=arguments,
                next_step=next_step or exc.next_step,
                leading=leading,
                rule=exc.rule,
            )
        )
    return upstream_error_result(
        exc, tool=tool, arguments=arguments, next_step=next_step, error_fields=leading
    )


def argument_error_result(
    exc: ValidationError,
    *,
    tool: str,
    arguments: Mapping[str, Any],
    leading: Mapping[str, Any] | None = None,
) -> CallToolResult:
    errors = exc.errors(include_url=False, include_context=False, include_input=False)
    problems: list[str] = []
    for error in errors:
        argument = ".".join(str(part) for part in error["loc"])
        problems.append(f"{argument}: {error['msg']}" if argument else error["msg"])
    return error_result(
        error_envelope(
            code=InvalidArgument.code,
            message=_bounded_line(
                agent_text.ARGUMENTS_REJECTED.format(problems="; ".join(problems))
            ),
            http_status=None,
            tool=tool,
            arguments=arguments,
            next_step=agent_text.ARGUMENTS_REJECTED_NEXT_STEP,
            leading=leading,
        )
    )


def _reject_blank_identifiers(arguments: Mapping[str, Any]) -> None:
    # The SDK leaves dots in path segments unencoded, and "." or ".." would normalize to
    # another endpoint.
    for name, value in arguments.items():
        if (
            name in _IDENTIFIER_LIST_TOOLS
            and isinstance(value, str)
            and value.strip() in {"", ".", ".."}
        ):
            raise InvalidArgument(agent_text.INVALID_IDENTIFIER.format(argument=name))


def reports_expected_errors[**P, R](
    fn: Callable[P, Awaitable[R]],
    *,
    error_fields: Mapping[str, Any] | None = None,
) -> Callable[P, Awaitable[R | CallToolResult]]:
    """Report an expected failure escaping a tool body as a structured error, led by
    ``error_fields`` (or by an ``OperationFailure``'s own leading state)."""
    signature = inspect.signature(fn)
    tool_name = getattr(fn, "__name__", type(fn).__name__)

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | CallToolResult:
        arguments = signature.bind(*args, **kwargs).arguments
        try:
            _reject_blank_identifiers(arguments)
            return await fn(*args, **kwargs)
        except OperationFailure as exc:
            return _failure_result(
                exc.cause,
                tool=tool_name,
                arguments=arguments,
                leading=exc.leading,
                next_step=exc.next_step,
            )
        except _REPORTED_ERRORS as exc:
            return _failure_result(exc, tool=tool_name, arguments=arguments, leading=error_fields)

    return wrapper
