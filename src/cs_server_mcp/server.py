"""Stateful Streamable HTTP MCP server with twelve Cobalt Strike tools."""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from sys import float_info
from typing import Annotated, Any, cast

import uvicorn
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools.base import Tool
from mcp.server.request_state import RequestStateSecurity
from mcp.types import InputRequiredResult, ToolAnnotations
from pydantic import AwareDatetime, Field
from pydantic_core import to_json
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

from cs_server_mcp import __version__, agent_text
from cs_server_mcp.approval import (
    ApprovalFailed,
    ApprovalRequests,
    ApprovalRequired,
    build_approval_requester,
)
from cs_server_mcp.artifact_upload import (
    UploadRejected,
    UploadSlot,
    UploadSlots,
    artifact_upload_name,
    read_upload_body,
    store_artifact,
)
from cs_server_mcp.client import ClientCall, CobaltStrikeClient
from cs_server_mcp.command_errors import CommandSelectionError
from cs_server_mcp.command_help import with_help_appendices
from cs_server_mcp.command_lifecycle import (
    GLOBAL_CATALOG_BEACON_ID,
    build_receipt,
    enrich_execution_diagnostics,
    get_task,
    list_commands,
    observe_execution,
    present_command_catalog,
    present_execution_list,
    read_new_task,
    reread_untouched_task,
    select_command,
    serialize_command_arguments,
    submission_failure,
    validate_command_request,
)
from cs_server_mcp.command_output_text import read_command_output
from cs_server_mcp.command_policy import (
    ApprovalRequester,
    CommandPolicy,
    CommandPolicyError,
    approval_failure,
    build_approval_summary,
    evaluate_command_policy,
    policy_refusal,
)
from cs_server_mcp.config import (
    BIND_HOST,
    DEFAULT_PORT,
    BindOptions,
    ConfigurationError,
    Settings,
    load_settings,
    resolve_password,
)
from cs_server_mcp.downloads import list_active_downloads
from cs_server_mcp.file_transfer import (
    FILES_ROUTE,
    FileStaging,
    StagedFile,
    capture_file_label,
    fallback_file_name,
    generic_file_name,
    public_base_url,
    transfer_file_name,
)
from cs_server_mcp.listing_pages import ROWS_KEY, ListingRequest, rows_key
from cs_server_mcp.output_contracts import (
    ArtifactListPage,
    ArtifactUploadLink,
    Beacons,
    CommandCatalog,
    Downloads,
    DownloadTransfer,
    ExecutionHistory,
    ExecutionReceipt,
    Screenshots,
    ScreenshotTransfer,
)
from cs_server_mcp.resource_views import (
    ARTIFACT_REFERENCE_PREFIX,
    identifier,
    isoformat,
    local_page,
    lookup,
    present_artifact,
    present_artifact_size,
    present_beacon,
    present_beacon_list,
    present_download,
    present_screenshot,
    regex_filter,
    sort_newest_first,
)
from cs_server_mcp.serialization import (
    Measure,
    bound_response,
    serialized_size,
    structured_size,
    to_plain_data,
)
from cs_server_mcp.tool_errors import (
    UPSTREAM_ERRORS,
    InvalidArgument,
    http_status_code,
    reports_expected_errors,
    upstream_error_result,
)
from cs_server_mcp.tool_schema import (
    ArtifactListLimit,
    ArtifactSearch,
    BeaconListLimit,
    CommandListLimit,
    CommandSearch,
    DownloadListLimit,
    DownloadSearch,
    ExecutionListLimit,
    ExecutionOrderField,
    ExecutionSearch,
    ExecutionStatus,
    Offset,
    ScreenshotListLimit,
    ScreenshotSearch,
    TeamServerSection,
    closed_tool,
)

_OUTPUT_DEFAULT_LIMIT = 2_000
_OUTPUT_MAX_LIMIT = 10_000
_OUTPUT_READ_DEADLINE_SECONDS = 60.0
_TEAM_SERVER_SETTINGS: Mapping[str, str] = {
    "teamserver_ip": "get_teamserver_ip",
    "kill_date": "get_kill_date",
    "c2_profile": "get_c2_profile",
    "system_information": "get_system_information",
}
_TEAM_SERVER_BLOCKS = frozenset({"c2_profile", "system_information"})


def _team_server_text(values: Mapping[str, str]) -> str:
    lines = [
        agent_text.TEAM_SERVER_LINE.format(name=name, value=value)
        for name, value in values.items()
        if value and name not in _TEAM_SERVER_BLOCKS
    ]
    parts = ["\n".join(lines)] if lines else []
    parts.extend(
        agent_text.TEAM_SERVER_BLOCK.format(name=name, value=value)
        for name, value in values.items()
        if value and name in _TEAM_SERVER_BLOCKS
    )
    return "\n\n".join(parts)


async def _execute_command_for_model(
    call_cs: ClientCall,
    *,
    beacon_id: str,
    command_name: str,
    arguments: Sequence[str] | None = None,
    policy: CommandPolicy,
    request_approval: ApprovalRequester,
) -> dict[str, Any] | InputRequiredResult:
    submitted_arguments = list(arguments) if arguments is not None else []
    validate_command_request(command_name=command_name)
    early = evaluate_command_policy(policy, command_name=command_name)
    if early.outcome == "deny":
        raise policy_refusal(command_name, rule=early.rule)
    # The help and submission endpoints accept nonexistent beacon IDs, the catalog's "0"
    # included, so the target is checked first.
    beacon = await call_cs("get_beacon", beacon_id)
    selected = await select_command(call_cs, beacon_id, command_name)
    command_name = selected["name"]
    builtin = "builtin" in (selected.get("groups") or [])
    # Rechecked with the resolved name and its groups, so a letter-case variant cannot
    # escape a name rule and group rules apply.
    decision = evaluate_command_policy(
        policy, command_name=command_name, groups=selected.get("groups") or []
    )
    if decision.outcome == "deny":
        raise policy_refusal(command_name, rule=decision.rule)
    console_arguments = serialize_command_arguments(submitted_arguments, command=selected)
    if decision.outcome == "ask":
        pending = await _collect_approval(
            request_approval,
            summary=build_approval_summary(command_name=command_name, arguments=console_arguments),
            binding=_approval_binding(
                beacon_id=beacon_id,
                command_name=command_name,
                submitted_arguments=submitted_arguments,
                command_definition=selected,
            ),
            rule=decision.rule,
        )
        if pending is not None:
            return pending
    submitted = await _submit_command(
        call_cs,
        beacon_id=beacon_id,
        command_name=command_name,
        console_arguments=console_arguments,
    )
    return build_receipt(
        submitted,
        beacon_id=beacon_id,
        command_name=command_name,
        arguments=console_arguments,
        submitted_arguments=submitted_arguments,
        task=await _accepted_task(call_cs, submitted, builtin=builtin),
        builtin=builtin,
        beacon=beacon,
    )


def _approval_binding(
    *,
    beacon_id: str,
    command_name: str,
    submitted_arguments: Sequence[str],
    command_definition: Mapping[str, Any],
) -> str:
    """What the user's consent is bound to, so a changed command cannot reuse an approval."""
    return json.dumps(
        {
            "beacon_id": beacon_id,
            "command_name": command_name,
            "submitted_arguments": list(submitted_arguments),
            "command_definition": command_definition,
        },
        sort_keys=True,
    )


async def _accepted_task(
    call_cs: ClientCall, submitted: Mapping[str, Any], *, builtin: bool
) -> Mapping[str, Any] | None:
    """The task an accepted submission created, read while the team server may still be
    listing it; None when it cannot be read in time."""
    task_id = submitted.get("taskId")
    if not isinstance(task_id, str) or not task_id:
        return None
    task = await read_new_task(call_cs, task_id)
    if task is not None and builtin:
        return await reread_untouched_task(call_cs, task_id, task)
    return task


async def _list_commands_for_model(
    call_cs: ClientCall,
    *,
    beacon_id: str | None,
    command_name: str | None,
    search_regex: str | None,
    include_help: bool | None,
    limit: int | None,
    offset: int | None,
    settings: Settings,
    policy: CommandPolicy,
) -> dict[str, Any]:
    """A lookup of a denied command is refused like a submission; a listing leaves denied
    commands out."""
    if command_name is not None and not command_name.strip():
        command_name = None
    if command_name is not None and search_regex is not None:
        raise InvalidArgument(agent_text.COMMAND_SEARCH_CONFLICT)
    if include_help is None:
        include_help = command_name is not None
    if command_name is not None:
        validate_command_request(command_name=command_name)
    beacon_id = GLOBAL_CATALOG_BEACON_ID if beacon_id is None else beacon_id
    if beacon_id != GLOBAL_CATALOG_BEACON_ID:
        await call_cs("get_beacon", beacon_id)
    if command_name is None:
        rows = await list_commands(call_cs, beacon_id)
    else:
        selected = await select_command(call_cs, beacon_id, command_name)
        decision = evaluate_command_policy(
            policy, command_name=selected["name"], groups=selected.get("groups") or []
        )
        if decision.outcome == "deny":
            raise policy_refusal(selected["name"], rule=decision.rule, lookup=True)
        rows = [
            await with_help_appendices(call_cs, beacon_id, selected) if include_help else selected
        ]
    return present_command_catalog(
        rows,
        include_help=include_help,
        search_regex=search_regex,
        limit=limit,
        offset=offset,
        settings=settings,
        policy=policy,
    )


def _upload_answer(status: int, body: Mapping[str, Any]) -> Response:
    return Response(
        to_json(body, fallback=str, indent=2),
        status_code=status,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


async def _collect_approval(
    request_approval: ApprovalRequester,
    *,
    summary: str,
    binding: str,
    rule: str | None,
) -> InputRequiredResult | None:
    """None once approved; the input-required result a modern client must answer first; a
    ``CommandPolicyError`` when approval broke down or was not granted."""
    try:
        outcome = await request_approval(summary, binding)
    except ApprovalRequired as exc:
        return exc.result
    except ApprovalFailed as exc:
        raise CommandPolicyError(
            "approval_failed", exc.message, rule=rule, next_step=exc.next_step
        ) from exc
    if outcome != "approved":
        raise approval_failure(outcome, rule=rule)
    return None


async def _submit_command(
    call_cs: ClientCall,
    *,
    beacon_id: str,
    command_name: str,
    console_arguments: str,
) -> dict[str, Any]:
    # Never retried: a failure past this point may mean the command was queued.
    try:
        return await call_cs(
            "execute_console_command",
            beacon_id,
            command=command_name,
            arguments=console_arguments,
        )
    except UPSTREAM_ERRORS as exc:
        raise submission_failure(exc) from exc


READ_TOOL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)
WRITE_TOOL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=True,
)
READ_TOOL_META = {"cs": {"impact": "read", "sensitivity": "metadata"}}
READ_CONTENT_TOOL_META = {"cs": {"impact": "read", "sensitivity": "content"}}
WRITE_TOOL_META = {"cs": {"impact": "execute_on_beacon", "sensitivity": "content"}}
# Each call creates a new usable link, so neither read-only nor idempotent.
TRANSFER_TOOL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=True,
)
TRANSFER_TOOL_META = {"cs": {"impact": "stage_transfer", "sensitivity": "content"}}
UPLOAD_TOOL_META = {"cs": {"impact": "store_on_server", "sensitivity": "content"}}
# Stated as five minutes in the fetch and upload tool descriptions.
TRANSFER_LINK_TTL_SECONDS = 300.0
CLIENT_VERIFICATION_ATTEMPTS = 3
CLIENT_VERIFICATION_RETRY_SECONDS = 1.0
CLIENT_VERIFICATION_AUTH_FAILURES = frozenset({401, 403})
CLIENT_VERIFICATION_RETRYABLE_STATUSES = frozenset({408, 425, 429})


async def _verify_service_account(client: CobaltStrikeClient) -> None:
    for attempt in range(1, CLIENT_VERIFICATION_ATTEMPTS + 1):
        try:
            await client.login()
            await client.get_teamserver_ip()
            return
        except UPSTREAM_ERRORS as exc:
            status = http_status_code(exc)
            if status in CLIENT_VERIFICATION_AUTH_FAILURES:
                raise ConfigurationError(
                    "Cobalt Strike rejected the service account login"
                ) from None
            if (
                status is not None
                and 400 <= status < 500
                and status not in CLIENT_VERIFICATION_RETRYABLE_STATUSES
            ):
                raise ConfigurationError(
                    f"Cobalt Strike startup probe failed with HTTP {status}"
                ) from None
            if attempt == CLIENT_VERIFICATION_ATTEMPTS:
                # Not chained: the transport error could carry the team server URL.
                raise ConfigurationError(
                    "Could not verify the Cobalt Strike service account after "
                    f"{CLIENT_VERIFICATION_ATTEMPTS} attempts"
                ) from None
        await asyncio.sleep(CLIENT_VERIFICATION_RETRY_SECONDS)


def _http_url(port: int) -> str:
    return f"http://{BIND_HOST}:{port}"


async def _structured_json_text(ctx: ServerRequestContext, call_next: CallNext) -> HandlerResult:
    """Send a successful result as structuredContent alone; mirror an error into text.

    Clients hand the model structuredContent when a success carries it, and Codex Code Mode
    hands a script the whole result, so a text copy would reach that model twice. Claude Code
    reads only the text of an isError result, so an error keeps a text block rendered from
    the same dump. See the mcp-harness skill.
    """
    result = await call_next(ctx)
    if ctx.method != "tools/call" or not isinstance(result, dict):
        return result
    structured = result.get("structuredContent")
    content = result.get("content")
    if structured is None or not _is_lone_text_block(content):
        return result
    if result.get("isError") is not True:
        return {**result, "content": []}
    text = to_json(structured, fallback=str, indent=2).decode()
    return {**result, "content": [{**content[0], "text": text}]}


def _is_lone_text_block(content: Any) -> bool:
    return (
        isinstance(content, list)
        and len(content) == 1
        and isinstance(content[0], dict)
        and content[0].get("type") == "text"
    )


def shapes_response(
    fn: Callable[..., Awaitable[Any]],
    *,
    max_chars: int,
    measure: Measure = serialized_size,
) -> Callable[..., Awaitable[Any]]:
    """Cap a tool's result at ``max_chars``: a listing is cut at a record boundary, anything
    else has only its free text shortened."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        request = ListingRequest(arguments=kwargs)
        result = await fn(*args, **kwargs)
        if rows_key(result) is not None:
            return request.bound(result, max_chars=max_chars, measure=measure)
        return bound_response(result, max_chars=max_chars, measure=measure)

    return wrapper


def checks_plain_text_response(
    fn: Callable[..., Awaitable[Any]], *, max_chars: int
) -> Callable[..., Awaitable[str]]:
    """A plain-text result over the ceiling is an error; no line is ever shortened."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        result = await fn(*args, **kwargs)
        if not isinstance(result, str):
            raise TypeError("Plain-text tool returned a non-text result")
        if len(result) > max_chars:
            raise ToolError(agent_text.PLAIN_TEXT_OVER_CEILING.format(max_chars=max_chars))
        return result

    return wrapper


def _add_http_routes(
    server: MCPServer,
    *,
    cs_client: CobaltStrikeClient,
    staging: FileStaging,
    uploads: UploadSlots,
    settings: Settings,
) -> None:
    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @server.custom_route("/readyz", methods=["GET"], include_in_schema=False)
    async def readyz(_request: Request) -> JSONResponse:
        try:
            await cs_client.get_teamserver_ip()
        except Exception:
            return JSONResponse({"status": "not_ready"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @server.custom_route(f"{FILES_ROUTE}/{{token}}", methods=["GET"], include_in_schema=False)
    async def fetch_staged_file(request: Request) -> Response:
        staged = staging.claim(request.path_params["token"])
        if staged is None:
            return JSONResponse(
                {
                    "detail": agent_text.TRANSFER_LINK_UNKNOWN,
                    "next_step": agent_text.TRANSFER_LINK_NEXT_STEP,
                },
                status_code=404,
            )
        return FileResponse(
            staged.path,
            media_type=staged.media_type,
            filename=staged.filename,
            background=BackgroundTask(staging.discard, staged),
            headers={"Cache-Control": "no-store"},
        )

    async def stored_artifact(name: str) -> dict[str, Any]:
        reference = f"{ARTIFACT_REFERENCE_PREFIX}{name}"
        try:
            rows = to_plain_data(await cs_client.list_artifacts())
        except UPSTREAM_ERRORS:
            rows = []
        if any(present_artifact(row)["artifact_reference"] == reference for row in rows):
            return {"artifact_reference": reference}
        return {"artifact_reference": reference, "notice": agent_text.UPLOAD_NOT_LISTED_NOTICE}

    @server.custom_route(f"{FILES_ROUTE}/{{token}}", methods=["PUT"], include_in_schema=False)
    async def receive_upload(request: Request) -> Response:
        slot = uploads.claim(request.path_params["token"])
        if slot is None:
            return _upload_answer(
                404,
                {
                    "detail": agent_text.UPLOAD_LINK_UNKNOWN,
                    "next_step": agent_text.NEW_LINK_NEXT_STEP,
                },
            )
        length = request.headers.get("content-length")
        try:
            content, digest = await read_upload_body(
                request.stream(),
                declared_length=int(length) if length and length.isdigit() else None,
                max_bytes=settings.max_upload_bytes,
            )
            store_artifact(
                settings.artifacts_directory, name=slot.name, content=content, digest=digest
            )
        except UploadRejected as exc:
            return _upload_answer(exc.status, {"detail": exc.detail, "next_step": exc.next_step})
        return _upload_answer(
            201,
            {
                **await stored_artifact(slot.name),
                "size_bytes": len(content),
                "sha256": digest,
            },
        )


def create_server(
    settings: Settings | None = None,
    *,
    port: int = DEFAULT_PORT,
    client: CobaltStrikeClient | None = None,
    staging: FileStaging | None = None,
    upload_slots: UploadSlots | None = None,
) -> MCPServer:
    """``port`` only names the origin a transfer link falls back to when the request names
    none. Tests inject ``client``, ``staging``, and ``upload_slots``."""
    resolved_settings = settings or load_settings()
    cs_client = (
        client
        if client is not None
        else CobaltStrikeClient(resolved_settings, password=resolve_password(resolved_settings))
    )
    approval_requests = ApprovalRequests()
    file_staging = staging or FileStaging(ttl_seconds=TRANSFER_LINK_TTL_SECONDS)
    pending_uploads = (
        upload_slots
        if upload_slots is not None
        else UploadSlots(ttl_seconds=TRANSFER_LINK_TTL_SECONDS)
    )

    @asynccontextmanager
    async def lifespan(_server: MCPServer):
        try:
            async with cs_client:
                await _verify_service_account(cs_client)
                yield {}
        finally:
            file_staging.close()
            pending_uploads.close()
            approval_requests.pending.clear()

    tools: list[Tool] = []

    def tool(
        *, error_fields: Mapping[str, Any] | None = None, **registration: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        # Wraps each body, innermost first: response cap (measured on the validated dump when
        # there is an output contract), expected-error reporting, closed input schema.
        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            plain_text = registration.get("structured_output") is False
            output_model = Tool.from_function(
                fn, structured_output=registration.get("structured_output")
            ).fn_metadata.output_model
            shaped = (
                checks_plain_text_response(fn, max_chars=resolved_settings.max_response_chars)
                if plain_text
                else shapes_response(
                    fn,
                    max_chars=resolved_settings.max_response_chars,
                    measure=serialized_size
                    if output_model is None
                    else structured_size(output_model),
                )
            )
            tools.append(
                closed_tool(
                    reports_expected_errors(shaped, error_fields=error_fields),
                    ceilings=resolved_settings.argument_ceilings(),
                    error_fields=error_fields,
                    **registration,
                )
            )
            return fn

        return register

    policy = resolved_settings.command_policy

    async def call_cs(method_name: str, *args: Any, **kwargs: Any) -> Any:
        return to_plain_data(await getattr(cs_client, method_name)(*args, **kwargs))

    def page(
        rows: list[dict[str, Any]], resource: str, limit: int | None, offset: int | None
    ) -> dict[str, Any]:
        return local_page(
            rows, limit=limit, offset=offset, resource=resource, settings=resolved_settings
        )

    fallback_base_url = _http_url(port)

    def one_time_link(ctx: Context, link: StagedFile | UploadSlot) -> dict[str, Any]:
        request = getattr(ctx.request_context, "request", None)
        return {
            "url": public_base_url(request, fallback_base_url) + link.url_path,
            "expires_at": isoformat(link.expires_at.replace(microsecond=0)),
        }

    async def stage_transfer(
        ctx: Context,
        open_method: str,
        resource_id: str,
        *,
        resource: str,
        list_tool: str,
        fallback: str | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        try:
            stream = await getattr(cs_client, open_method)(resource_id)
        except UPSTREAM_ERRORS as exc:
            if http_status_code(exc) == 404:
                raise CommandSelectionError(
                    "not_found",
                    agent_text.TRANSFER_VANISHED.format(resource=resource),
                    next_step=agent_text.TRANSFER_VANISHED_NEXT_STEP.format(list_tool=list_tool),
                    http_status=404,
                ) from None
            raise
        suggested = None if generic_file_name(stream.filename, resource) else stream.filename

        def file_name(media_type: str) -> str:
            # The suggested name, else the record's own, else screenshot-<label>.png and the like.
            generated = fallback_file_name(
                resource, label or resource_id, media_type, stream.filename
            )
            return transfer_file_name(suggested, transfer_file_name(fallback, generated))

        staged = await file_staging.stage(stream, name_for=file_name)
        transfer = {
            f"{resource}_id": resource_id,
            **one_time_link(ctx, staged),
            "size_bytes": staged.size_bytes,
            "sha256": staged.sha256,
        }
        # Every screenshot is suggested as screenshot.jpg, so only a download reports one.
        if resource == "download":
            transfer["source_filename"] = stream.filename
        return transfer

    @tool(
        title=agent_text.LIST_BEACONS_TITLE,
        description=agent_text.LIST_BEACONS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_beacons(
        beacon_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_BEACONS_BEACON_ID),
        ] = None,
        include_dead: Annotated[
            bool,
            Field(description=agent_text.LIST_BEACONS_INCLUDE_DEAD),
        ] = False,
        limit: BeaconListLimit = None,
        offset: Offset = None,
    ) -> Beacons:
        if beacon_id is not None:
            return cast(Beacons, present_beacon(await call_cs("get_beacon", beacon_id)))
        rows = present_beacon_list(await call_cs("list_beacons"), include_dead=include_dead)
        return cast(Beacons, page(rows, "beacons", limit, offset))

    @tool(
        title=agent_text.LIST_COMMANDS_TITLE,
        description=agent_text.LIST_COMMANDS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_commands(
        beacon_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_COMMANDS_BEACON_ID),
        ] = None,
        command_name: Annotated[
            str | None,
            Field(description=agent_text.LIST_COMMANDS_COMMAND_NAME),
        ] = None,
        search_regex: CommandSearch = None,
        include_help: Annotated[
            bool | None,
            Field(description=agent_text.LIST_COMMANDS_INCLUDE_HELP),
        ] = None,
        limit: CommandListLimit = None,
        offset: Offset = None,
    ) -> CommandCatalog:
        return cast(
            CommandCatalog,
            await _list_commands_for_model(
                call_cs,
                beacon_id=beacon_id,
                command_name=command_name,
                search_regex=search_regex,
                include_help=include_help,
                limit=limit,
                offset=offset,
                settings=resolved_settings,
                policy=policy,
            ),
        )

    @tool(
        title=agent_text.EXECUTE_COMMAND_TITLE,
        description=agent_text.EXECUTE_COMMAND,
        annotations=WRITE_TOOL_ANNOTATIONS,
        meta=WRITE_TOOL_META,
        # A failure escaping the body happened before submission; the body reports the rest.
        error_fields={"submission_outcome": "not_submitted"},
    )
    async def cs_execute_command(
        ctx: Context,
        beacon_id: Annotated[
            str,
            Field(description=agent_text.EXECUTE_COMMAND_BEACON_ID),
        ],
        command_name: Annotated[
            str,
            Field(description=agent_text.EXECUTE_COMMAND_COMMAND_NAME),
        ],
        command_arguments: Annotated[
            list[str] | None,
            Field(description=agent_text.EXECUTE_COMMAND_COMMAND_ARGUMENTS),
        ] = None,
    ) -> ExecutionReceipt | InputRequiredResult:
        return cast(
            ExecutionReceipt | InputRequiredResult,
            await _execute_command_for_model(
                call_cs,
                beacon_id=beacon_id,
                command_name=command_name,
                arguments=command_arguments,
                policy=policy,
                request_approval=build_approval_requester(
                    ctx,
                    requests=approval_requests,
                ),
            ),
        )

    @tool(
        title=agent_text.LIST_COMMAND_EXECUTIONS_TITLE,
        description=agent_text.LIST_COMMAND_EXECUTIONS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_command_executions(
        command_execution_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_COMMAND_EXECUTIONS_COMMAND_EXECUTION_ID),
        ] = None,
        beacon_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_COMMAND_EXECUTIONS_BEACON_ID),
        ] = None,
        search_regex: ExecutionSearch = None,
        order_by: Annotated[
            list[ExecutionOrderField] | None,
            Field(min_length=1, description=agent_text.LIST_COMMAND_EXECUTIONS_ORDER_BY),
        ] = None,
        status: Annotated[
            ExecutionStatus | None,
            Field(description=agent_text.LIST_COMMAND_EXECUTIONS_STATUS),
        ] = None,
        since: Annotated[
            AwareDatetime | None,
            Field(description=agent_text.LIST_COMMAND_EXECUTIONS_SINCE),
        ] = None,
        limit: ExecutionListLimit = None,
        offset: Offset = None,
    ) -> ExecutionHistory:
        if command_execution_id is not None:
            return cast(
                ExecutionHistory,
                await observe_execution(call_cs, await get_task(call_cs, command_execution_id)),
            )
        rows = (
            await call_cs("list_beacon_tasks", beacon_id)
            if beacon_id is not None
            else await call_cs("list_tasks")
        )
        listing = present_execution_list(
            rows,
            settings=resolved_settings,
            search_regex=search_regex,
            order_by=order_by,
            status=status,
            since=since,
            limit=limit,
            offset=offset,
        )
        return cast(
            ExecutionHistory,
            await enrich_execution_diagnostics(
                call_cs, listing, timeout_seconds=resolved_settings.request_timeout_seconds
            ),
        )

    @tool(
        title=agent_text.READ_COMMAND_OUTPUT_TITLE,
        description=agent_text.READ_COMMAND_OUTPUT,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_CONTENT_TOOL_META,
        structured_output=False,
    )
    async def cs_read_command_output(
        command_execution_id: Annotated[
            str,
            Field(description=agent_text.READ_COMMAND_OUTPUT_COMMAND_EXECUTION_ID),
        ],
        start_line: Annotated[
            int,
            Field(
                ge=1,
                description=agent_text.READ_COMMAND_OUTPUT_START_LINE,
            ),
        ] = 1,
        max_lines: Annotated[
            int | None,
            Field(
                ge=1,
                le=_OUTPUT_MAX_LIMIT,
                description=(
                    agent_text.READ_COMMAND_OUTPUT_MAX_LINES.format(
                        default=_OUTPUT_DEFAULT_LIMIT, max=_OUTPUT_MAX_LIMIT
                    )
                ),
            ),
        ] = None,
    ) -> str:
        return await read_command_output(
            call_cs,
            command_execution_id,
            start_line=start_line,
            max_lines=_OUTPUT_DEFAULT_LIMIT if max_lines is None else max_lines,
            max_page_chars=resolved_settings.max_response_chars,
            read_timeout_seconds=_OUTPUT_READ_DEADLINE_SECONDS,
            wait_seconds=resolved_settings.output_wait_seconds,
        )

    @tool(
        title=agent_text.LIST_ARTIFACTS_TITLE,
        description=agent_text.LIST_ARTIFACTS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_artifacts(
        search_regex: ArtifactSearch = None,
        limit: ArtifactListLimit = None,
        offset: Offset = None,
    ) -> ArtifactListPage:
        rows = [present_artifact(row) for row in await call_cs("list_artifacts")]
        rows = [
            row for row in rows if row["artifact_reference"].startswith(ARTIFACT_REFERENCE_PREFIX)
        ]
        rows = regex_filter(rows, search_regex, agent_text.ARTIFACT_SEARCH_FIELDS)
        rows.sort(key=lambda row: row["artifact_reference"])
        listing = page(rows, "artifacts", limit, offset)
        # Sizes are read from disk, so only for the page returned.
        listing[ROWS_KEY] = [
            present_artifact_size(row, resolved_settings.artifacts_directory)
            for row in listing[ROWS_KEY]
        ]
        return cast(ArtifactListPage, listing)

    @tool(
        title=agent_text.UPLOAD_ARTIFACT_TITLE,
        description=agent_text.UPLOAD_ARTIFACT,
        annotations=TRANSFER_TOOL_ANNOTATIONS,
        meta=UPLOAD_TOOL_META,
    )
    async def cs_upload_artifact(
        ctx: Context,
        artifact_name: Annotated[
            str,
            Field(description=agent_text.UPLOAD_ARTIFACT_ARTIFACT_NAME),
        ],
    ) -> ArtifactUploadLink:
        slot = pending_uploads.open(name=artifact_upload_name(artifact_name))
        return cast(
            ArtifactUploadLink,
            {**one_time_link(ctx, slot), "max_bytes": resolved_settings.max_upload_bytes},
        )

    async def completed_downloads(beacons: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        hosts = {identifier(beacon, "bid"): beacon.get("computer") or None for beacon in beacons}
        return [
            present_download(row, host=hosts.get(identifier(row, "bid")))
            for row in await call_cs("list_downloads")
        ]

    @tool(
        title=agent_text.LIST_DOWNLOADS_TITLE,
        description=agent_text.LIST_DOWNLOADS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_downloads(
        download_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_DOWNLOADS_DOWNLOAD_ID),
        ] = None,
        beacon_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_DOWNLOADS_BEACON_ID),
        ] = None,
        search_regex: DownloadSearch = None,
        limit: DownloadListLimit = None,
        offset: Offset = None,
        include_active: Annotated[
            bool,
            Field(description=agent_text.LIST_DOWNLOADS_INCLUDE_ACTIVE),
        ] = True,
    ) -> Downloads:
        beacons = await call_cs("list_beacons")
        rows = await completed_downloads(beacons)
        if download_id is not None:
            return cast(Downloads, lookup(rows, "download_id", download_id, "cs_list_downloads"))
        if beacon_id is not None:
            rows = [row for row in rows if row["beacon_id"] == beacon_id]
        sort_newest_first(rows, timestamp_field="downloaded_at", id_field="download_id")
        if include_active:
            try:
                active = await list_active_downloads(
                    call_cs,
                    beacons=beacons,
                    beacon_id=beacon_id,
                    timeout_seconds=resolved_settings.request_timeout_seconds,
                )
            except UPSTREAM_ERRORS as exc:
                # Returned rather than raised: the next step names include_active, which the
                # generic upstream envelope cannot know about.
                return cast(
                    Downloads,
                    upstream_error_result(
                        exc,
                        tool="cs_list_downloads",
                        arguments={"beacon_id": beacon_id},
                        next_step=agent_text.ACTIVE_DOWNLOADS_FAILED_NEXT_STEP,
                    ),
                )
            rows = active + rows
        rows = regex_filter(rows, search_regex, agent_text.DOWNLOAD_SEARCH_FIELDS)
        return cast(Downloads, page(rows, "downloads", limit, offset))

    @tool(
        title=agent_text.FETCH_DOWNLOAD_TITLE,
        description=agent_text.FETCH_DOWNLOAD,
        annotations=TRANSFER_TOOL_ANNOTATIONS,
        meta=TRANSFER_TOOL_META,
    )
    async def cs_fetch_download(
        ctx: Context,
        download_id: Annotated[
            str,
            Field(description=agent_text.FETCH_DOWNLOAD_DOWNLOAD_ID),
        ],
    ) -> DownloadTransfer:
        download = lookup(
            await completed_downloads(await call_cs("list_beacons")),
            "download_id",
            download_id,
            "cs_list_downloads",
        )
        staged = await stage_transfer(
            ctx,
            "open_download_file",
            download_id,
            resource="download",
            list_tool="cs_list_downloads",
            fallback=download["remote_file_name"],
        )
        origin = ("beacon_id", "host", "remote_file_name", "remote_directory", "transfer_state")
        return cast(
            DownloadTransfer,
            {**staged, **{key: download[key] for key in origin if key in download}},
        )

    async def listed_screenshots() -> list[dict[str, Any]]:
        return [present_screenshot(row) for row in await call_cs("list_screenshots")]

    @tool(
        title=agent_text.LIST_SCREENSHOTS_TITLE,
        description=agent_text.LIST_SCREENSHOTS,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_TOOL_META,
    )
    async def cs_list_screenshots(
        screenshot_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_SCREENSHOTS_SCREENSHOT_ID),
        ] = None,
        beacon_id: Annotated[
            str | None,
            Field(description=agent_text.LIST_SCREENSHOTS_BEACON_ID),
        ] = None,
        search_regex: ScreenshotSearch = None,
        limit: ScreenshotListLimit = None,
        offset: Offset = None,
    ) -> Screenshots:
        rows = await listed_screenshots()
        if screenshot_id is not None:
            return cast(
                Screenshots, lookup(rows, "screenshot_id", screenshot_id, "cs_list_screenshots")
            )
        if beacon_id is not None:
            rows = [row for row in rows if row["beacon_id"] == beacon_id]
        rows = regex_filter(rows, search_regex, agent_text.SCREENSHOT_SEARCH_FIELDS)
        sort_newest_first(rows, timestamp_field="created_at", id_field="screenshot_id")
        return cast(Screenshots, page(rows, "screenshots", limit, offset))

    @tool(
        title=agent_text.FETCH_SCREENSHOT_TITLE,
        description=agent_text.FETCH_SCREENSHOT,
        annotations=TRANSFER_TOOL_ANNOTATIONS,
        meta=TRANSFER_TOOL_META,
    )
    async def cs_fetch_screenshot(
        ctx: Context,
        screenshot_id: Annotated[
            str,
            Field(description=agent_text.FETCH_SCREENSHOT_SCREENSHOT_ID),
        ],
    ) -> ScreenshotTransfer:
        screenshot = lookup(
            await listed_screenshots(), "screenshot_id", screenshot_id, "cs_list_screenshots"
        )
        staged = await stage_transfer(
            ctx,
            "open_screenshot_image",
            screenshot_id,
            resource="screenshot",
            list_tool="cs_list_screenshots",
            label=capture_file_label(
                screenshot["created_at"], screenshot["window_title"], screenshot_id
            ),
        )
        origin = ("beacon_id", "created_at")
        return cast(ScreenshotTransfer, {**staged, **{key: screenshot[key] for key in origin}})

    @tool(
        title=agent_text.GET_TEAM_SERVER_TITLE,
        description=agent_text.GET_TEAM_SERVER,
        annotations=READ_TOOL_ANNOTATIONS,
        meta=READ_CONTENT_TOOL_META,
        structured_output=False,
    )
    async def cs_get_team_server(
        section: Annotated[
            TeamServerSection | None,
            Field(description=agent_text.GET_TEAM_SERVER_SECTION),
        ] = None,
    ) -> str:
        if section is not None:
            return await call_cs(_TEAM_SERVER_SETTINGS[section])
        return _team_server_text(
            {name: await call_cs(method) for name, method in _TEAM_SERVER_SETTINGS.items()}
        )

    server = MCPServer(
        "Cobalt Strike MCP",
        instructions=agent_text.SERVER_INSTRUCTIONS,
        version=__version__,
        lifespan=lifespan,
        middleware=[_structured_json_text],
        tools=tools,
        # The SDK requires a finite TTL; state stays valid for the process lifetime.
        request_state_security=RequestStateSecurity.ephemeral(ttl=float_info.max),
    )

    _add_http_routes(
        server,
        cs_client=cs_client,
        staging=file_staging,
        uploads=pending_uploads,
        settings=resolved_settings,
    )
    return server


def create_asgi_app(settings: Settings | None = None, *, bind: BindOptions = BindOptions()) -> Any:
    resolved_settings = settings or load_settings()
    return create_server(resolved_settings, port=bind.port).streamable_http_app(
        host=BIND_HOST,
        streamable_http_path=bind.mcp_path,
        stateless_http=False,
        session_idle_timeout=resolved_settings.session_idle_timeout_seconds,
    )


def run(config_path: str | None = None, *, bind: BindOptions = BindOptions()) -> None:
    resolved_settings = load_settings(config_path)
    app = create_asgi_app(resolved_settings, bind=bind)
    print(f"Serving MCP at {_http_url(bind.port)}{bind.mcp_path}", file=sys.stderr)
    uvicorn.run(app, host=BIND_HOST, port=bind.port, log_config=None)
