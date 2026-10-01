"""Focused read-only queries backed by the existing OpenAPI operation handlers."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import Tool, ToolResult
from pydantic import Field


QUERY_OPERATIONS = {
    "getServerConfiguration": (
        "getTeamserverIp", "getSystemInformation", "getC2Profile", "getKillDate",
    ),
    "queryTasks": ("listTasks", "listTasksByBid", "listTaskSummariesByBid"),
    "queryListeners": ("listListeners", "getListenerByName"),
    "queryCredentials": ("listCredentials", "getCredential"),
    "queryCommandHelp": ("listCommandHelp", "getCommandHelp"),
    "listExecutionMethods": (
        "listRemoteExecutionCommandMethods", "listRemoteExecuteBeaconMethods",
        "listElevateCommandMethods", "listElevateBeaconMethods",
    ),
    "queryScreenshots": ("listScreenshots", "getScreenshot"),
    "queryKeyStrokes": ("listKeyStrokes", "getKeyStrokesByBid"),
}
GROUPED_OPERATION_NAMES = frozenset(
    operation for operations in QUERY_OPERATIONS.values() for operation in operations
)
QUERY_TOOL_NAMES = frozenset(QUERY_OPERATIONS)


def _nonempty(value: str, name: str) -> str:
    """Reject an empty selector instead of accidentally broadening a query."""
    if not value.strip():
        raise ToolError(f"{name} must not be empty")
    return value


def add_cobalt_strike_query_tools(
    mcp_server: FastMCP, operation_tools: dict[str, Tool],
) -> None:
    """Group existing handlers without changing their request/result semantics.

    Capture only handlers admitted by the server's OpenAPI route policy. The
    original operation names are hidden from MCP clients by the final catalog
    allowlist, while these wrappers retain direct references to their handlers.
    """
    operations = {
        name: tool for name, tool in operation_tools.items()
        if name in GROUPED_OPERATION_NAMES
    }

    async def invoke(operation: str, arguments: dict) -> ToolResult:
        tool = operations.get(operation)
        if tool is None:
            raise ToolError(f"Operation {operation} is unavailable in the current API specification")
        # Preserve FastMCP's parameter serialization, the authenticated HTTP
        # adapter, error handling, and structured/content results unchanged.
        return await tool.run(arguments)

    async def getServerConfiguration(
        section: Annotated[
            Literal["teamserver_ip", "system_information", "c2_profile", "kill_date"],
            Field(description="Configuration section to return; exactly one section is returned."),
        ],
    ) -> ToolResult:
        """Read one server configuration section; returns only the selected section."""
        operation = {
            "teamserver_ip": "getTeamserverIp",
            "system_information": "getSystemInformation",
            "c2_profile": "getC2Profile",
            "kill_date": "getKillDate",
        }[section]
        return await invoke(operation, {})

    async def queryTasks(
        bid: Annotated[
            str | None,
            Field(description="Beacon ID. Omit to list global full tasks."),
        ] = None,
        view: Annotated[
            Literal["full", "summary"],
            Field(description="Task view; defaults to full. Summary requires a Beacon ID."),
        ] = "full",
        format: Annotated[
            Literal["plain", "structured"] | None,
            Field(description="Optional API format for full Beacon tasks only; omission preserves the API default."),
        ] = None,
    ) -> ToolResult:
        """List tasks globally or for one Beacon, preserving the selected API result.

        Omit bid for all tasks (full view only). Supply bid for full tasks or
        summaries. format is supported only for full tasks with bid; omitting it
        preserves the API default. Use getTaskById to retrieve an individual task.
        """
        if bid is None:
            if view != "full" or format is not None:
                raise ToolError("Task summaries and format require bid")
            return await invoke("listTasks", {})
        arguments = {"bid": _nonempty(bid, "bid")}
        if view == "summary":
            if format is not None:
                raise ToolError("format is only supported for view='full' with bid")
            return await invoke("listTaskSummariesByBid", arguments)
        if format is not None:
            arguments["format"] = format
        return await invoke("listTasksByBid", arguments)

    async def queryListeners(
        name: Annotated[
            str | None,
            Field(description="Exact listener name. Omit to list all listeners."),
        ] = None,
    ) -> ToolResult:
        """List listeners, or retrieve one by its exact name when name is supplied."""
        if name is None:
            return await invoke("listListeners", {})
        return await invoke("getListenerByName", {"name": _nonempty(name, "name")})

    async def queryCredentials(
        id: Annotated[
            UUID | None,
            Field(description="Credential UUID. Omit to list all credentials."),
        ] = None,
    ) -> ToolResult:
        """List credentials, or retrieve one by UUID. Use addCredential to add a record."""
        if id is None:
            return await invoke("listCredentials", {})
        return await invoke("getCredential", {"id": str(id)})

    async def queryCommandHelp(
        bid: Annotated[str, Field(description="Exact Beacon ID returned by the Beacon inventory.")],
        command: Annotated[
            str | None,
            Field(description="Exact Beacon command name. Omit to list available commands."),
        ] = None,
    ) -> ToolResult:
        """List available commands for a Beacon, or get help for one command."""
        arguments = {"bid": _nonempty(bid, "bid")}
        if command is None:
            return await invoke("listCommandHelp", arguments)
        arguments["command"] = _nonempty(command, "command")
        return await invoke("getCommandHelp", arguments)

    async def listExecutionMethods(
        bid: Annotated[str, Field(description="Exact Beacon ID returned by the Beacon inventory.")],
        kind: Annotated[
            Literal["remote_command", "remote_beacon", "elevate_command", "elevate_beacon"],
            Field(description="Execution or elevation method category to list; this tool never executes a method."),
        ],
    ) -> ToolResult:
        """List methods available to a Beacon for one execution/elevation category.

        remote_command and remote_beacon list remote execution methods;
        elevate_command and elevate_beacon list elevation methods. This query
        only lists methods and does not execute them.
        """
        operation = {
            "remote_command": "listRemoteExecutionCommandMethods",
            "remote_beacon": "listRemoteExecuteBeaconMethods",
            "elevate_command": "listElevateCommandMethods",
            "elevate_beacon": "listElevateBeaconMethods",
        }[kind]
        return await invoke(operation, {"bid": _nonempty(bid, "bid")})

    async def queryScreenshots(
        id: Annotated[
            str | None,
            Field(description="Screenshot ID. Omit to list existing screenshots."),
        ] = None,
    ) -> ToolResult:
        """List existing screenshots, or retrieve one by ID; does not capture new screenshots."""
        if id is None:
            return await invoke("listScreenshots", {})
        return await invoke("getScreenshot", {"id": _nonempty(id, "id")})

    async def queryKeyStrokes(
        bid: Annotated[
            str | None,
            Field(description="Beacon ID. Omit to list existing keystroke records globally."),
        ] = None,
    ) -> ToolResult:
        """Read existing keystroke records globally or for one Beacon; does not start collection."""
        if bid is None:
            return await invoke("listKeyStrokes", {})
        return await invoke("getKeyStrokesByBid", {"bid": _nonempty(bid, "bid")})

    for query in (
        getServerConfiguration, queryTasks, queryListeners, queryCredentials,
        queryCommandHelp, listExecutionMethods, queryScreenshots, queryKeyStrokes,
    ):
        if any(name in operations for name in QUERY_OPERATIONS[query.__name__]):
            mcp_server.tool(
                # Results retain the selected handler's structured content and
                # content blocks; the different operations have different shapes.
                output_schema=None,
                annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
            )(query)
