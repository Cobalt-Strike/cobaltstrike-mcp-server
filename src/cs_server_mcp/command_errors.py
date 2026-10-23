"""Command selection errors shared by catalog lookups, local lookups, and submissions."""

from __future__ import annotations

from cs_server_mcp import agent_text


class CommandSelectionError(ValueError):
    def __init__(self, code: str, message: str, *, next_step: str, http_status: int | None = None):
        super().__init__(
            agent_text.SELECTION_ERROR_TEXT.format(message=message, next_step=next_step)
        )
        self.code = code
        self.message = message
        self.next_step = next_step
        self.http_status = http_status
        # Set by policy decisions only.
        self.rule: str | None = None
