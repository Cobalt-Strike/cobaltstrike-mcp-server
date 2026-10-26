"""MCP approval transport for legacy prompts and modern input-required rounds."""

from __future__ import annotations

import json
from hashlib import sha256
from secrets import token_urlsafe

import anyio
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.types import (
    METHOD_NOT_FOUND,
    ClientCapabilities,
    ElicitationCapability,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import ValidationError

from cs_server_mcp import agent_text
from cs_server_mcp.command_policy import APPROVAL_SCHEMA, ApprovalOutcome, ApprovalRequester

_APPROVAL_PROGRESS_INTERVAL_SECONDS = 60
# Bounds prompts a client abandoned without answering.
_MAX_PENDING_APPROVALS = 10_000


class ApprovalRequired(Exception):
    """Suspend the call while a modern client collects consent in a round of its own."""

    def __init__(self, result: InputRequiredResult):
        self.result = result


class ApprovalFailed(Exception):
    """The approval round broke down before the user's answer could count."""

    def __init__(self, message: str, next_step: str = agent_text.APPROVAL_RETRY_NEXT_STEP):
        super().__init__(message)
        self.message = message
        self.next_step = next_step


def approval_outcome(result: ElicitResult) -> ApprovalOutcome:
    # Content is ignored: Codex sends none for a message-only form.
    if result.action == "accept":
        return "approved"
    if result.action == "decline":
        return "declined"
    if result.action == "cancel":
        return "canceled"
    raise ApprovalFailed(agent_text.APPROVAL_UNEXPECTED_RESPONSE)


class ApprovalRequests:
    """Single-use approval tickets, one instance per server.

    MCPServer already seals request_state against the tool arguments and principal;
    the tickets add replay protection and bind consent to the resolved command definition.
    """

    def __init__(self) -> None:
        self.pending: dict[str, str] = {}

    def request(self, ctx: Context, summary: str, binding: str) -> ApprovalOutcome:
        digest = sha256(f"{summary}\0{binding}".encode()).hexdigest()
        if ctx.request_state is not None:
            try:
                state = json.loads(ctx.request_state)
                ticket = self.pending.pop(state["approval_id"], None)
            except (ValueError, KeyError, TypeError):
                raise ApprovalFailed(agent_text.APPROVAL_INVALID_STATE) from None
            if ticket is None:
                raise ApprovalFailed(agent_text.APPROVAL_EXPIRED)
            if ticket != digest:
                raise ApprovalFailed(agent_text.APPROVAL_COMMAND_CHANGED)
            response = (ctx.input_responses or {}).get("approval")
            if not isinstance(response, ElicitResult):
                raise ApprovalFailed(agent_text.APPROVAL_MISSING_RESPONSE)
            return approval_outcome(response)
        if ctx.input_responses:
            raise ApprovalFailed(agent_text.APPROVAL_NO_PENDING_REQUEST)
        if len(self.pending) >= _MAX_PENDING_APPROVALS:
            raise ApprovalFailed(
                agent_text.APPROVAL_TOO_MANY_PENDING,
                agent_text.APPROVAL_TOO_MANY_PENDING_NEXT_STEP,
            )
        approval_id = token_urlsafe(32)
        self.pending[approval_id] = digest
        raise ApprovalRequired(
            InputRequiredResult(
                input_requests={
                    "approval": ElicitRequest(
                        params=ElicitRequestFormParams(
                            message=summary,
                            requested_schema=APPROVAL_SCHEMA,
                        )
                    )
                },
                request_state=json.dumps({"approval_id": approval_id}),
            )
        )


def build_approval_requester(
    ctx: Context,
    *,
    requests: ApprovalRequests,
) -> ApprovalRequester:
    async def report_progress() -> None:
        # Keeps client idle timers alive while the user considers the prompt.
        progress = 0
        while True:
            await ctx.report_progress(progress)
            await anyio.sleep(_APPROVAL_PROGRESS_INTERVAL_SECONDS)
            progress += 1

    async def prompt(summary: str) -> ElicitResult:
        # Not ctx.elicit: it rejects the content-less accept Codex sends for a message-only form.
        try:
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(report_progress)
                result = await ctx.session.elicit_form(
                    summary, APPROVAL_SCHEMA, related_request_id=ctx.request_id
                )
                tasks.cancel_scope.cancel()
        except ExceptionGroup as exc:
            if len(exc.exceptions) == 1:
                raise exc.exceptions[0] from None
            raise
        return result

    async def request_approval(summary: str, binding: str) -> ApprovalOutcome:
        if not ctx.session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability())
        ):
            return "unavailable"
        if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
            return requests.request(ctx, summary, binding)
        # An unhandled MCPError would fail the call as a protocol error naming no
        # submission outcome, which a model cannot tell from a lost reply.
        try:
            result = await prompt(summary)
        except NoBackChannelError:
            return "unavailable"
        except MCPError as exc:
            if exc.code == METHOD_NOT_FOUND:
                return "unavailable"
            raise ApprovalFailed(agent_text.APPROVAL_PROMPT_ERROR) from exc
        except ValidationError as exc:
            raise ApprovalFailed(agent_text.APPROVAL_UNEXPECTED_RESPONSE) from exc
        return approval_outcome(result)

    return request_approval
