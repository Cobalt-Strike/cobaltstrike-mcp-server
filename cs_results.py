"""Public MCP result conversion for the repository's custom helpers."""

from __future__ import annotations

import json
from typing import Any

from fastmcp.tools import ToolResult

from cs_client import mcp_error


OBJECT_RESULT_SCHEMA = {"type": "object", "additionalProperties": True}


def submission_result(result: dict[str, Any]) -> dict[str, Any]:
    """Keep a lost submission response distinct from a definite rejection."""
    if result.get("ok") is False and result.get("error_code") in {"transport_error", "invalid_response"}:
        return {
            **result,
            **mcp_error(
                "The task submission outcome is unknown.",
                error_code="submission_uncertain",
                error_stage=result.get("error_stage", "transport"),
                resolution="Inspect existing tasks before deciding whether to submit again; do not automatically replay this request.",
            ),
            "task_submitted": None,
            "submission_state": "unknown",
        }
    return result


def tool_result(result: dict[str, Any]) -> ToolResult:
    """Serialize one helper-owned envelope, never inspecting target data."""
    payload = dict(result)
    is_error = payload.get("ok") is False or bool(payload.get("error"))
    if is_error:
        # HTTP helpers retain raw diagnostic detail internally. It is not part
        # of the public error contract and may echo secrets from an upstream API.
        payload.pop("exception", None)
    return ToolResult(
        content=json.dumps(payload, ensure_ascii=False),
        structured_content=payload,
        is_error=is_error,
    )
