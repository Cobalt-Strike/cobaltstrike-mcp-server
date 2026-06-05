"""MCP tools for Cobalt Strike Beacon interpreter lint and execution."""

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
SCRIPT_FILE_REFERENCE_RE = re.compile(r"^@files/([A-Za-z0-9._-]+)$")
SCRIPT_ARTIFACT_REFERENCE_RE = re.compile(r"^@artifacts/[A-Za-z0-9._:/-]+$")
ARGUMENT_TYPES = {"binary", "int", "short", "str", "wideStr"}
INT_MIN = -(2**31)
INT_MAX = 2**31 - 1
SHORT_MIN = -(2**15)
SHORT_MAX = 2**15 - 1


def add_cobalt_strike_interpreter_tools(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP tools for Cobalt Strike Beacon Interpreter C lint and execution."""

    @mcp_server.tool()
    async def lintBeaconInterpreterC(
        bid: str,
        script: str,
        files: dict[str, str] | None = None,
    ) -> str:
        """Lint Beacon Interpreter C source using /execute/interpreter/lint.

        The script value may be inline C source or a symbolic reference such as
        @files/script.c or @artifacts/scripts/script.c. Values in files must be
        base64 content keyed by file name when a @files reference is used.
        """
        audit_event(
            "tool_invocation",
            tool_name="lintBeaconInterpreterC",
            beacon_id=str(bid),
            status="started",
            details={"script": _audit_script_value(script), "file_count": _safe_len(files)},
        )
        result = await lint_interpreter_c_code(
            cs_client,
            bid=bid,
            script=script,
            files=files,
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
        files: dict[str, str] | None = None,
    ) -> str:
        """Execute Beacon Interpreter C source using /execute/interpreter/pack.

        The API now packs typed arguments server-side. Pass arguments as an array
        of objects with type one of binary, int, short, str, or wideStr.
        """
        audit_event(
            "tool_invocation",
            tool_name="runBeaconInterpreterC",
            beacon_id=str(bid),
            status="started",
            details={
                "script": _audit_script_value(script),
                "file_count": _safe_len(files),
                "argument_count": _safe_len(arguments),
            },
        )
        result = await run_interpreter_c_code(
            cs_client,
            bid=bid,
            script=script,
            arguments=arguments,
            files=files,
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
    files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Submit interpreter C source to the Beacon lint endpoint."""
    try:
        encoded_bid = quote(validate_beacon_id(bid), safe="")
        payload = build_interpreter_payload(script=script, files=files)
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
    files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Submit interpreter C source to the Beacon pack endpoint."""
    try:
        encoded_bid = quote(validate_beacon_id(bid), safe="")
        payload = build_interpreter_payload(script=script, files=files)
        if arguments is not None:
            payload["arguments"] = normalize_interpreter_arguments(arguments)
    except ValueError as exc:
        return mcp_error("Invalid interpreter execution request", exception=str(exc))

    return await cs_client.request_json(
        "POST",
        f"/api/v1/beacons/{encoded_bid}/execute/interpreter/pack",
        json=payload,
    )


def build_interpreter_payload(
    *,
    script: str,
    files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the REST payload for interpreter lint/pack requests."""
    script_value = _require_script(script)
    payload_files = normalize_interpreter_files(files)

    file_reference = SCRIPT_FILE_REFERENCE_RE.fullmatch(script_value.strip())
    if file_reference:
        file_name = file_reference.group(1)
        if file_name not in payload_files:
            raise ValueError(f"files must include {file_name!r} when script references @files/{file_name}")
        return {"script": script_value.strip(), "files": payload_files}

    if SCRIPT_ARTIFACT_REFERENCE_RE.fullmatch(script_value.strip()):
        payload: dict[str, Any] = {"script": script_value.strip()}
        if payload_files:
            payload["files"] = payload_files
        return payload

    if script_value.strip().startswith("@"):
        raise ValueError("script must be inline C source, @files/<file>, or @artifacts/<path>")

    if DEFAULT_SCRIPT_FILE_NAME in payload_files:
        raise ValueError(f"files cannot include {DEFAULT_SCRIPT_FILE_NAME!r} when script is inline source")

    payload_files[DEFAULT_SCRIPT_FILE_NAME] = _encode_inline_source(script_value)
    return {
        "script": f"@files/{DEFAULT_SCRIPT_FILE_NAME}",
        "files": payload_files,
    }


def normalize_interpreter_files(files: dict[str, str] | None) -> dict[str, str]:
    """Validate a file map according to the interpreter API schema."""
    if files is None:
        return {}
    if not isinstance(files, dict):
        raise ValueError("files must be an object mapping file names to base64 content")

    normalized: dict[str, str] = {}
    for file_name, content in files.items():
        normalized_name = _normalize_file_name(file_name)
        normalized[normalized_name] = _normalize_base64(content, f"files[{normalized_name!r}]")
    return normalized


def normalize_interpreter_arguments(arguments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate typed arguments and return the API-native pack argument array."""
    if not isinstance(arguments, list):
        raise ValueError("arguments must be a list")

    normalized: list[dict[str, Any]] = []
    for index, argument in enumerate(arguments):
        if not isinstance(argument, dict):
            raise ValueError(f"arguments[{index}] must be an object")
        if "type" not in argument:
            raise ValueError(f"arguments[{index}].type is required")
        if "value" not in argument:
            raise ValueError(f"arguments[{index}].value is required")

        arg_type = argument["type"]
        if arg_type not in ARGUMENT_TYPES:
            allowed = ", ".join(sorted(ARGUMENT_TYPES))
            raise ValueError(f"arguments[{index}].type must be one of: {allowed}")

        value = argument["value"]
        if arg_type == "binary":
            _require_string(value, f"arguments[{index}].value")
            _validate_base64(value, f"arguments[{index}].value")
        elif arg_type == "int":
            _require_integer(value, INT_MIN, INT_MAX, f"arguments[{index}].value")
        elif arg_type == "short":
            _require_integer(value, SHORT_MIN, SHORT_MAX, f"arguments[{index}].value")
        else:
            _require_string(value, f"arguments[{index}].value")

        normalized.append({"type": arg_type, "value": value})

    return normalized


def _require_script(script: str) -> str:
    if not isinstance(script, str):
        raise ValueError("script must be a string")
    if not script.strip():
        raise ValueError("script is required")
    return script


def _require_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def _require_integer(value: Any, minimum: int, maximum: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")


def _encode_inline_source(script: str) -> str:
    return base64.b64encode(script.encode("utf-8")).decode("ascii")


def _normalize_base64(value: Any, field_name: str) -> str:
    _require_string(value, field_name)
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


def _audit_script_value(script: Any) -> str:
    if isinstance(script, str):
        stripped = script.strip()
        if SCRIPT_FILE_REFERENCE_RE.fullmatch(stripped) or SCRIPT_ARTIFACT_REFERENCE_RE.fullmatch(stripped):
            return stripped
    return "<inline-source>"


def _safe_len(value: Any) -> int:
    try:
        return len(value or [])
    except TypeError:
        return 0
