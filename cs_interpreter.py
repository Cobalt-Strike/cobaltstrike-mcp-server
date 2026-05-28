"""MCP tools for safe usage of the Cobalt Strike interpreter."""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any
from urllib.parse import quote

from fastmcp import FastMCP

from cs_audit import audit_event
from cs_client import CobaltStrikeClient, mcp_error
from cs_streams import validate_beacon_id

logger = logging.getLogger(__name__)

DEFAULT_SCRIPT_FILE_NAME = "script.c"
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ARGUMENT_TYPE_CODES = {
    "b": "b",
    "binary": "b",
    "i": "i",
    "int": "i",
    "integer": "i",
    "s": "s",
    "short": "s",
    "z": "z",
    "str": "z",
    "string": "z",
    "Z": "Z",
    "widestr": "Z",
    "wideStr": "Z",
    "wide_str": "Z",
    "wide-string": "Z",
}
INT_MIN = -(2**31)
INT_MAX = 2**31 - 1
SHORT_MIN = -(2**15)
SHORT_MAX = 2**15 - 1


def add_cobalt_strike_interpreter_tools(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP tools for Cobalt Strike Beacon interpreter C lint and execution."""

    @mcp_server.tool()
    async def lintBeaconInterpreterC(
        bid: str,
        script: str,
        script_is_base64: bool = False,
        script_file_name: str = DEFAULT_SCRIPT_FILE_NAME,
        files: dict[str, str] | None = None,
        files_are_base64: bool = False,
    ) -> str:
        """Lint Beacon interpreter C source using /execute/interpreter/lint."""
        audit_event(
            "tool_invocation",
            tool_name="lintBeaconInterpreterC",
            beacon_id=str(bid),
            status="started",
            details={"script_file_name": script_file_name, "extra_file_count": len(files or {})},
        )
        result = await lint_interpreter_c_code(
            cs_client,
            bid=bid,
            script=script,
            script_is_base64=script_is_base64,
            script_file_name=script_file_name,
            files=files,
            files_are_base64=files_are_base64,
        )
        audit_event(
            "tool_invocation",
            tool_name="lintBeaconInterpreterC",
            beacon_id=str(bid),
            status="completed" if result.get("ok") else "failed",
            details={"endpoint": result.get("endpoint"), "status_code": result.get("status_code")},
        )
        return json.dumps(result, indent=2)

    @mcp_server.tool()
    async def runBeaconInterpreterC(
        bid: str,
        script: str,
        arguments: list[dict[str, Any]] | None = None,
        script_is_base64: bool = False,
        script_file_name: str = DEFAULT_SCRIPT_FILE_NAME,
        files: dict[str, str] | None = None,
        files_are_base64: bool = False,
    ) -> str:
        """Execute Beacon interpreter C source using /execute/interpreter."""
        audit_event(
            "tool_invocation",
            tool_name="runBeaconInterpreterC",
            beacon_id=str(bid),
            status="started",
            details={
                "script_file_name": script_file_name,
                "extra_file_count": len(files or {}),
                "argument_count": len(arguments or []),
            },
        )
        result = await run_interpreter_c_code(
            cs_client,
            bid=bid,
            script=script,
            arguments=arguments,
            script_is_base64=script_is_base64,
            script_file_name=script_file_name,
            files=files,
            files_are_base64=files_are_base64,
        )
        audit_event(
            "tool_invocation",
            tool_name="runBeaconInterpreterC",
            beacon_id=str(bid),
            status="completed" if result.get("ok") else "failed",
            details={"endpoint": result.get("endpoint"), "status_code": result.get("status_code")},
        )
        return json.dumps(result, indent=2)

    logger.info("Added MCP interpreter tools")


async def lint_interpreter_c_code(
    cs_client: CobaltStrikeClient,
    *,
    bid: str,
    script: str,
    script_is_base64: bool = False,
    script_file_name: str = DEFAULT_SCRIPT_FILE_NAME,
    files: dict[str, str] | None = None,
    files_are_base64: bool = False,
) -> dict[str, Any]:
    """Submit interpreter C source to the Beacon lint endpoint."""
    try:
        encoded_bid = quote(validate_beacon_id(bid), safe="")
        payload = build_interpreter_payload(
            script=script,
            script_is_base64=script_is_base64,
            script_file_name=script_file_name,
            files=files,
            files_are_base64=files_are_base64,
        )
    except ValueError as exc:
        return mcp_error("Invalid interpreter lint request", exception=str(exc))

    return await cs_client.request_json(
        "POST",
        f"/api/v1/beacons/{encoded_bid}/execute/interpreter/lint",
        json=payload,
    )


async def run_interpreter_c_code(
    cs_client: CobaltStrikeClient,
    *,
    bid: str,
    script: str,
    arguments: list[dict[str, Any]] | None = None,
    script_is_base64: bool = False,
    script_file_name: str = DEFAULT_SCRIPT_FILE_NAME,
    files: dict[str, str] | None = None,
    files_are_base64: bool = False,
) -> dict[str, Any]:
    """Submit interpreter C source to the Beacon execution endpoint."""
    try:
        encoded_bid = quote(validate_beacon_id(bid), safe="")
        payload = build_interpreter_payload(
            script=script,
            script_is_base64=script_is_base64,
            script_file_name=script_file_name,
            files=files,
            files_are_base64=files_are_base64,
        )
        if arguments is not None:
            payload["arguments"] = build_interpreter_arguments(arguments)
    except ValueError as exc:
        return mcp_error("Invalid interpreter execution request", exception=str(exc))

    return await cs_client.request_json(
        "POST",
        f"/api/v1/beacons/{encoded_bid}/execute/interpreter",
        json=payload,
    )


def build_interpreter_payload(
    *,
    script: str,
    script_is_base64: bool = False,
    script_file_name: str = DEFAULT_SCRIPT_FILE_NAME,
    files: dict[str, str] | None = None,
    files_are_base64: bool = False,
) -> dict[str, Any]:
    """Build the REST payload for interpreter lint/execute requests."""
    normalized_script_file_name = _normalize_file_name(script_file_name)
    encoded_files: dict[str, str] = {}

    for file_name, content in (files or {}).items():
        normalized_file_name = _normalize_file_name(file_name)
        encoded_files[normalized_file_name] = _encode_file_content(content, is_base64=files_are_base64)

    encoded_files[normalized_script_file_name] = _encode_file_content(script, is_base64=script_is_base64)

    return {
        "script": f"@files/{normalized_script_file_name}",
        "files": encoded_files,
    }


def build_interpreter_arguments(arguments: list[dict[str, Any]]) -> str:
    """Convert structured argument descriptors into Cobalt Strike packed argument syntax."""
    if not isinstance(arguments, list):
        raise ValueError("arguments must be a list")

    type_codes: list[str] = []
    values: list[str] = []

    for index, argument in enumerate(arguments):
        if not isinstance(argument, dict):
            raise ValueError(f"arguments[{index}] must be an object")
        if "type" not in argument:
            raise ValueError(f"arguments[{index}].type is required")
        if "value" not in argument:
            raise ValueError(f"arguments[{index}].value is required")

        type_code = _argument_type_code(argument["type"])
        type_codes.append(type_code)
        values.append(_format_argument_value(type_code, argument["value"], index))

    return " ".join([_quote_argument("".join(type_codes)), *values])


def _argument_type_code(raw_type: Any) -> str:
    key = str(raw_type).strip()
    type_code = ARGUMENT_TYPE_CODES.get(key) or ARGUMENT_TYPE_CODES.get(key.lower())
    if not type_code:
        raise ValueError(f"unsupported argument type: {raw_type!r}")
    return type_code


def _format_argument_value(type_code: str, value: Any, index: int) -> str:
    if type_code == "i":
        return str(_bounded_integer(value, INT_MIN, INT_MAX, f"arguments[{index}].value"))
    if type_code == "s":
        return str(_bounded_integer(value, SHORT_MIN, SHORT_MAX, f"arguments[{index}].value"))
    if type_code == "b":
        encoded = str(value)
        _validate_base64(encoded, f"arguments[{index}].value")
        return _quote_argument(encoded)
    return _quote_argument(str(value))


def _bounded_integer(value: Any, minimum: int, maximum: int, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not a boolean")
    try:
        integer = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if integer < minimum or integer > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return integer


def _quote_argument(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _encode_file_content(content: str, *, is_base64: bool) -> str:
    if is_base64:
        return _normalize_base64(str(content), "file content")
    return base64.b64encode(str(content).encode("utf-8")).decode("ascii")


def _normalize_base64(value: str, field_name: str) -> str:
    decoded = _validate_base64(value, field_name)
    return base64.b64encode(decoded).decode("ascii")


def _validate_base64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc


def _normalize_file_name(file_name: str) -> str:
    normalized = str(file_name).strip()
    if not FILE_NAME_RE.fullmatch(normalized):
        raise ValueError(
            "file names must be 1-128 characters and contain only letters, numbers, dots, underscores, or hyphens"
        )
    if normalized in {".", ".."}:
        raise ValueError("file name cannot be a relative path marker")
    return normalized
