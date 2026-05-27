"""Structured audit logging helpers for MCP operations."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUDIT_LOGGER_NAME = "cs_mcp.audit"

logger = logging.getLogger(AUDIT_LOGGER_NAME)


def configure_audit_logging(audit_log_file: str | None = None) -> None:
    """Configure optional dedicated JSONL audit logging."""
    logger.setLevel(logging.INFO)
    if not audit_log_file:
        return

    audit_path = Path(audit_log_file).expanduser()
    if audit_path.parent != Path("."):
        audit_path.parent.mkdir(parents=True, exist_ok=True)

    resolved_path = str(audit_path.resolve())
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and handler.baseFilename == resolved_path:
            return

    file_handler = logging.FileHandler(resolved_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.propagate = False


def audit_event(
    action: str,
    *,
    tool_name: str | None = None,
    operator_id: str | None = None,
    beacon_id: str | None = None,
    task_id: Any | None = None,
    status: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write one sanitized structured audit event."""
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "operator_id": operator_id or os.getenv("MCP_OPERATOR_ID"),
        "tool_name": tool_name,
        "beacon_id": beacon_id,
        "task_id": task_id,
        "status": status,
    }
    if details:
        event["details"] = {
            key: value
            for key, value in details.items()
            if value is not None
        }

    logger.info(json.dumps(_drop_none(event), sort_keys=True))


def _drop_none(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}
