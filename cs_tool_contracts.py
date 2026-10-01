"""Client-facing behavior and discovery metadata for published MCP tools."""

from __future__ import annotations

from collections.abc import Sequence

from fastmcp.server.transforms import GetToolNext, Transform
from fastmcp.tools import Tool
from fastmcp.utilities.versions import VersionSpec
from mcp.types import ToolAnnotations


ACTION_TOOL_NAMES = frozenset({
    "addCredential",
    "executeBeaconConsoleAndWait",
    "runBeaconInterpreterC",
})

DESTRUCTIVE_TOOL_NAMES = frozenset({
    "executeBeaconConsoleAndWait",
    "runBeaconInterpreterC",
})

TOOL_SEARCH_HINTS = {
    "addCredential": "credential credentials password passwords hash hashes secret secrets realm user store",
    "executeBeaconConsoleAndWait": "beacon command console task execute run output wait",
    "getBeacon": "beacon beacons session sessions callback host details",
    "getBeaconConsoleTail": "beacon console log logs output tail recent",
    "getDownload": "download downloads file files metadata record loot",
    "getDownloadedFileText": "download downloads file files document text content read extract loot",
    "getHostCallbackInformation": "host callback callbacks network beacon connection",
    "getLiveBeaconSnapshot": "live beacon beacons session sessions callbacks snapshot",
    "getPayloadStoreMetadata": "payload payloads artifact artifacts store metadata",
    "getServerConfiguration": "team server ip system information c2 profile kill date configuration",
    "getSyscallMethod": "syscall syscalls method beacon system call",
    "getTaskById": "task tasks job jobs result status identifier",
    "lintBeaconInterpreterC": "beacon interpreter c lint compile validate source code",
    "listActiveDownloads": "active download downloads transfers files loot",
    "listArtifacts": "artifact artifacts payload payloads files",
    "listBeacons": "beacon beacons session sessions callbacks agents hosts",
    "listDownloads": "download downloads files loot records",
    "listExecutionMethods": "remote execution execute elevate elevation privilege methods",
    "listHostProfiles": "host hosts profile profiles network callback",
    "listJobs": "job jobs running beacon tasks",
    "listTokenStore": "token tokens access token store credentials",
    "queryCommandHelp": "beacon command commands help syntax usage documentation",
    "queryCredentials": "credential credentials password passwords hashes secrets",
    "queryKeyStrokes": "keystroke keystrokes keylogger keyboard input records",
    "queryListeners": "listener listeners c2 endpoints payloads",
    "queryScreenshots": "screenshot screenshots image images desktop captures",
    "queryTasks": "task tasks job jobs results status beacon",
    "runBeaconInterpreterC": "beacon interpreter c execute run source code task",
}


def validate_tool_contract_names(published_names: set[str] | frozenset[str]) -> None:
    """Fail startup when behavior/search policy drifts from the public catalog."""
    expected = set(published_names)
    configured = set(TOOL_SEARCH_HINTS)
    if configured != expected:
        missing = sorted(expected - configured)
        unexpected = sorted(configured - expected)
        raise RuntimeError(
            "Tool contract metadata does not match the engagement catalog: "
            f"missing={missing}, unexpected={unexpected}"
        )
    if not DESTRUCTIVE_TOOL_NAMES <= ACTION_TOOL_NAMES:
        raise RuntimeError("Destructive tool policy contains a non-action tool")
    if not ACTION_TOOL_NAMES <= expected:
        raise RuntimeError("Action tool policy contains an unpublished tool")


def tool_annotations(name: str) -> ToolAnnotations:
    """Return explicit MCP behavior hints for one published tool."""
    read_only = name not in ACTION_TOOL_NAMES
    return ToolAnnotations(
        readOnlyHint=read_only,
        destructiveHint=name in DESTRUCTIVE_TOOL_NAMES,
        idempotentHint=read_only,
        openWorldHint=True,
    )


class CobaltStrikeToolContractTransform(Transform):
    """Apply behavior annotations and client search hints without renaming tools."""

    @staticmethod
    def _apply(tool: Tool) -> Tool:
        hint = TOOL_SEARCH_HINTS.get(tool.name)
        if hint is None:
            return tool
        meta = dict(tool.meta or {})
        meta["anthropic/searchHint"] = hint
        return tool.model_copy(
            update={
                "annotations": tool_annotations(tool.name),
                "meta": meta,
            }
        )

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [self._apply(tool) for tool in tools]

    async def get_tool(
        self,
        name: str,
        call_next: GetToolNext,
        *,
        version: VersionSpec | None = None,
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        return self._apply(tool) if tool is not None else None
