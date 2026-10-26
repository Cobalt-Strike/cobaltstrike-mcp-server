"""The published contract: the eleven tools, their annotations, the client text budgets, and
the lifespan. ``.agents/skills/mcp-harness/SKILL.md`` explains the budgets and rules."""

from __future__ import annotations

import json
from typing import NamedTuple, get_args

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.types import Tool

from cs_server_mcp.artifact_upload import UploadSlots
from cs_server_mcp.config import ConfigurationError
from cs_server_mcp.file_transfer import FileStaging
from cs_server_mcp.output_contracts import CommandRejection
from cs_server_mcp.server import create_server
from cs_server_mcp.tool_schema import ExecutionStatus
from tests.fake_teamserver import FakeTeamServer, api_error
from tests.harness import make_settings


class ToolContract(NamedTuple):
    """What ``tools/list`` must advertise for one tool."""

    required: list[str]
    read_only: bool
    destructive: bool
    idempotent: bool
    impact: str
    sensitivity: str


READ = ToolContract([], True, False, True, "read", "metadata")
TOOL_CONTRACTS = {
    "cs_list_beacons": READ,
    "cs_list_commands": READ,
    "cs_execute_command": ToolContract(
        ["beacon_id", "command_name"], False, True, False, "execute_on_beacon", "content"
    ),
    "cs_list_command_executions": READ,
    "cs_read_command_output": READ._replace(
        required=["command_execution_id"], sensitivity="content"
    ),
    "cs_list_artifacts": READ,
    "cs_upload_artifact": ToolContract(
        ["artifact_name"], False, False, False, "store_on_server", "content"
    ),
    "cs_list_downloads": READ,
    "cs_fetch_download": ToolContract(
        ["download_id"], False, False, False, "stage_transfer", "content"
    ),
    "cs_list_screenshots": READ,
    "cs_fetch_screenshot": ToolContract(
        ["screenshot_id"], False, False, False, "stage_transfer", "content"
    ),
}


def files_app(server: MCPServer):
    return server.streamable_http_app(
        host="127.0.0.1", streamable_http_path="/mcp", stateless_http=False
    )


async def advertised_tool(teamserver: FakeTeamServer, name: str) -> Tool:
    tools = await create_server(make_settings(), client=teamserver).list_tools()
    return next(tool for tool in tools if tool.name == name)


async def test_the_server_advertises_exactly_the_eleven_tools(teamserver: FakeTeamServer) -> None:
    tools = await create_server(make_settings(), client=teamserver).list_tools()

    assert sorted(tool.name for tool in tools) == sorted(TOOL_CONTRACTS)


@pytest.mark.parametrize("name", TOOL_CONTRACTS)
async def test_advertised_tool_declares_its_title_hints_and_impact(
    teamserver: FakeTeamServer, name: str
) -> None:
    # A wrong read_only_hint lets a write skip Codex's approval prompt.
    expected = TOOL_CONTRACTS[name]

    tool = await advertised_tool(teamserver, name)

    assert tool.input_schema.get("required", []) == expected.required
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is expected.read_only
    assert tool.annotations.destructive_hint is expected.destructive
    assert tool.annotations.idempotent_hint is expected.idempotent
    assert tool.annotations.open_world_hint is True
    assert tool.title and tool.annotations.title == tool.title
    assert tool.meta == {"cs": {"impact": expected.impact, "sensitivity": expected.sensitivity}}


async def test_server_instructions_fit_the_client_budget_and_lead_with_the_scope(
    teamserver: FakeTeamServer,
) -> None:
    # Codex silently cuts instructions at 1,000 bytes.
    server = create_server(make_settings(), client=teamserver)

    assert server.instructions is not None
    assert server.instructions.startswith("Tools for Cobalt Strike")
    assert len(server.instructions.encode()) <= 1000


@pytest.mark.parametrize("name", TOOL_CONTRACTS)
async def test_tool_text_fits_the_client_budgets_and_describes_every_argument(
    teamserver: FakeTeamServer, name: str
) -> None:
    # Codex silently cuts descriptions at 1,000 bytes and compacts schemas over 5,000.
    tool = await advertised_tool(teamserver, name)

    assert len((tool.description or "").encode()) <= 1000
    schema = tool.input_schema
    assert len(json.dumps(schema).encode()) <= 5_000
    assert schema.get("additionalProperties") is False
    for argument_name, argument in schema["properties"].items():
        assert argument.get("description"), f"{argument_name} has no description"
        branches = argument.get("anyOf", [argument])
        assert all("type" in branch for branch in branches), f"{argument_name} has no type"


async def test_tool_descriptions_explain_result_fields_the_model_cannot_see(
    teamserver: FakeTeamServer,
) -> None:
    # Claude Code never shows the model a tool's outputSchema.
    descriptions = {
        tool.name: " ".join((tool.description or "").split())
        for tool in await create_server(make_settings(), client=teamserver).list_tools()
    }

    executions = descriptions["cs_list_command_executions"]
    for status in get_args(ExecutionStatus):
        assert status in executions, f"cs_list_command_executions does not define {status}"
    for field in ("execution_status_message", "result_count", "error_count", "job_id"):
        assert field in executions, field
    execute = descriptions["cs_execute_command"]
    for field in ("submitted_arguments", "command_arguments", "execution_status_note"):
        assert field in execute, field
    outcomes = get_args(CommandRejection.model_fields["submission_outcome"].annotation)
    assert outcomes == ("not_submitted", "rejected", "uncertain")
    for outcome in outcomes:
        assert outcome in execute, f"cs_execute_command does not name {outcome}"
    beacons = descriptions["cs_list_beacons"]
    for field in ("is_admin", "last_checkin_age", "sleep_seconds", "jitter_percent", "note"):
        assert field in beacons, field
    downloads = descriptions["cs_list_downloads"]
    for field in ("transfer_state", "received_bytes", "progress", "downloaded_at"):
        assert field in downloads, field
    artifacts = descriptions["cs_list_artifacts"]
    for field in ("artifact_reference", "size_bytes"):
        assert field in artifacts, field


async def test_stopping_the_server_removes_staged_files_and_pending_upload_links(
    teamserver: FakeTeamServer,
) -> None:
    staging = FileStaging(ttl_seconds=60)
    slots = UploadSlots(ttl_seconds=60)
    server = create_server(make_settings(), client=teamserver, staging=staging, upload_slots=slots)
    slot = slots.open(name="hosts.txt")
    app = files_app(server)

    async with app.router.lifespan_context(app):
        assert staging.directory.exists()
        assert len(slots) == 1

    assert not staging.directory.exists()
    assert len(slots) == 0
    assert slots.claim(slot.token) is None


async def test_startup_retries_a_login_the_team_server_cannot_serve_yet(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.fail("login", api_error(503))
    app = files_app(create_server(make_settings(), client=teamserver))

    async with app.router.lifespan_context(app):
        pass

    assert teamserver.logins == 2


async def test_startup_fails_as_a_configuration_error_when_the_login_is_refused(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.fail("login", api_error(401))
    app = files_app(create_server(make_settings(), client=teamserver))

    with pytest.raises(ConfigurationError, match="rejected the service account login") as failure:
        async with app.router.lifespan_context(app):
            pass

    assert teamserver.logins == 1, "a refused login is not retried"
    assert failure.value.__suppress_context__ is True, "the transport error is not chained"
