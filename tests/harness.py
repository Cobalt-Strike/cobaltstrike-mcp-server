"""An MCP client connected to the server under test over the SDK's in-process transport,
through the same validation, middleware, and response ceiling as over HTTP."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal

import httpx
import pydantic
from mcp.client.client import Client
from mcp.client.session import ClientRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, ElicitRequestParams, ElicitResult

from cs_server_mcp.artifact_upload import UploadSlots
from cs_server_mcp.command_policy import CommandPolicy
from cs_server_mcp.config import Settings
from cs_server_mcp.file_transfer import FileStaging
from cs_server_mcp.server import TRANSFER_LINK_TTL_SECONDS, create_server
from tests.fake_teamserver import FakeTeamServer

TEAMSERVER_URL = "https://teamserver.example:50443"
ProtocolMode = Literal["2026-07-28", "legacy"]
PROTOCOL_MODES: tuple[ProtocolMode, ...] = ("2026-07-28", "legacy")


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "url": TEAMSERVER_URL,
        "username": "mcp-service",
        "password": "hunter2",
        "command_policy": CommandPolicy(default="allow"),
    }
    return Settings(**{**values, **overrides})


class ApprovalPrompts:
    def __init__(self, action: Literal["accept", "decline", "cancel"]) -> None:
        self.action = action
        self.messages: list[str] = []

    async def __call__(
        self, context: ClientRequestContext, params: ElicitRequestParams
    ) -> ElicitResult:
        self.messages.append(params.message)
        return ElicitResult(action=self.action)


@dataclass
class ConnectedServer:
    server: MCPServer
    client: Client
    staging: FileStaging
    uploads: UploadSlots

    async def call(self, tool: str, **arguments: Any) -> CallToolResult:
        return await self.client.call_tool(tool, arguments)

    def http(self) -> httpx.AsyncClient:
        """The server's HTTP routes, where transfer and upload links are served."""
        app = self.server.streamable_http_app(session_idle_timeout=None)
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:50051"
        )


@asynccontextmanager
async def connect(
    settings: Settings,
    teamserver: FakeTeamServer,
    *,
    mode: ProtocolMode = "2026-07-28",
    prompts: ApprovalPrompts | None = None,
) -> AsyncIterator[ConnectedServer]:
    """Without ``prompts`` the client declares no elicitation capability."""
    staging = FileStaging(ttl_seconds=TRANSFER_LINK_TTL_SECONDS)
    uploads = UploadSlots(ttl_seconds=TRANSFER_LINK_TTL_SECONDS)
    server = create_server(settings, client=teamserver, staging=staging, upload_slots=uploads)
    async with Client(
        server, mode=mode, elicitation_callback=prompts, raise_exceptions=True
    ) as client:
        yield ConnectedServer(server, client, staging, uploads)


def contract[ModelT: pydantic.BaseModel](result: CallToolResult, model: type[ModelT]) -> ModelT:
    assert result.is_error is not True, result.content
    assert result.structured_content is not None, "a structured tool sends structuredContent"
    assert result.content == [], "a successful structured result carries no text block"
    return model.model_validate(result.structured_content)


def error_payload(result: CallToolResult) -> dict[str, Any]:
    assert result.is_error is True, result.structured_content or result.content
    [block] = result.content
    assert block.type == "text"
    payload = result.structured_content
    assert payload is not None, "a tool error carries its envelope as structuredContent"
    assert json.loads(block.text) == payload
    return payload


def plain_text(result: CallToolResult) -> str:
    assert result.is_error is not True, result.content
    assert result.structured_content is None
    [block] = result.content
    assert block.type == "text"
    return block.text
