"""Closed input schemas with bounds and configured ceilings stated on each argument.

A fixed bound is a ``Field`` constraint the SDK enforces. A configured ceiling is not
enforced by the schema: the server clamps and reports the value it used, and
``ConfiguredCeiling`` lets ``closed_tool`` state the running server's value in the
description. Rules the schema cannot express are raised as ``InvalidArgument`` where the
request is built.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, cast

from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from mcp.server.mcpserver.tools.base import Tool
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cs_server_mcp import agent_text
from cs_server_mcp.config import LIST_LIMITS, SEARCH_REGEX_MAX_CHARS
from cs_server_mcp.tool_errors import argument_error_result


@dataclass(frozen=True)
class ConfiguredCeiling:
    """A key of ``Settings.argument_ceilings`` and a description with a ``{ceiling}`` placeholder."""

    setting: str
    description: str

    def describe(self, ceiling: int) -> str:
        return self.description.format(ceiling=ceiling)


Offset = Annotated[
    int | None,
    Field(
        ge=0,
        description=agent_text.OFFSET,
    ),
]


def _list_limit(resource: str) -> Any:
    return Annotated[
        int | None,
        Field(ge=1),
        ConfiguredCeiling(
            f"{resource}_list_limit",
            agent_text.LIST_LIMIT.format(
                default=LIST_LIMITS[resource].default, ceiling="{ceiling}"
            ),
        ),
    ]


BeaconListLimit = _list_limit("beacons")
CommandListLimit = _list_limit("commands")
ExecutionListLimit = _list_limit("command_executions")
ArtifactListLimit = _list_limit("artifacts")
DownloadListLimit = _list_limit("downloads")
ScreenshotListLimit = _list_limit("screenshots")

ExecutionOrderField = Literal[
    "id", "-id", "submitted_at", "-submitted_at", "updated_at", "-updated_at"
]
ExecutionStatus = Literal["in_progress", "output_received", "completed", "failed", "canceled"]
TeamServerSection = Literal["teamserver_ip", "kill_date", "c2_profile", "system_information"]


def _search_regex(
    fields: Mapping[str, str], *, suffix: str = agent_text.SEARCH_REGEX_LOOKUP_SUFFIX
) -> Any:
    return Annotated[
        str | None,
        Field(
            description=agent_text.SEARCH_REGEX.format(
                fields=", ".join(fields.values()),
                max_chars=SEARCH_REGEX_MAX_CHARS,
                suffix=suffix,
            ).strip()
        ),
    ]


CommandSearch = _search_regex(
    agent_text.COMMAND_SEARCH_FIELDS, suffix=agent_text.SEARCH_REGEX_COMMAND_SUFFIX
)
ExecutionSearch = _search_regex(agent_text.EXECUTION_SEARCH_FIELDS)
# Artifacts have no single-ID lookup, so the search applies to every call.
ArtifactSearch = _search_regex(agent_text.ARTIFACT_SEARCH_FIELDS, suffix="")
DownloadSearch = _search_regex(agent_text.DOWNLOAD_SEARCH_FIELDS)
ScreenshotSearch = _search_regex(agent_text.SCREENSHOT_SEARCH_FIELDS)


class ClosedTool(Tool):
    """Reports input-schema failures in the tool error envelope instead of pydantic's text.

    The SDK raises them before the body runs as a ``ToolError`` caused by a
    ``ValidationError``; a crash (``UnexpectedToolError``) keeps the SDK's handling.
    """

    error_fields: dict[str, Any] | None = Field(default=None, exclude=True)

    async def run(
        self, arguments: dict[str, Any], context: Any, convert_result: bool = False
    ) -> Any:
        try:
            return await super().run(arguments, context, convert_result)
        except UnexpectedToolError:
            raise
        except ToolError as exc:
            if not isinstance(exc.__cause__, ValidationError):
                raise
            result = argument_error_result(
                exc.__cause__, tool=self.name, arguments=arguments, leading=self.error_fields
            )
            return self.fn_metadata.convert_result(result) if convert_result else result


def closed_tool(
    fn: Callable[..., Any],
    *,
    ceilings: Mapping[str, int],
    error_fields: Mapping[str, Any] | None = None,
    **registration: Any,
) -> Tool:
    """Register ``fn`` with an input schema that rejects undeclared keys.

    The SDK's argument model otherwise ignores an unknown key, so a misspelled optional
    argument silently takes its default. The ``title`` is also copied to
    ``annotations.title``, which Claude Code shows in its permission prompt.
    """
    tool = cast(ClosedTool, ClosedTool.from_function(fn, **registration))
    tool.error_fields = dict(error_fields) if error_fields is not None else None
    if tool.title:
        tool.annotations = (tool.annotations or ToolAnnotations()).model_copy(
            update={"title": tool.title}
        )
    open_model = tool.fn_metadata.arg_model
    closed_model = type(
        open_model.__name__,
        (open_model,),
        {"__module__": open_model.__module__, "model_config": ConfigDict(extra="forbid")},
    )
    tool.fn_metadata.arg_model = closed_model
    tool.parameters = closed_model.model_json_schema(by_alias=True)
    _strip_titles(tool.parameters)
    _publish_ceilings(closed_model, tool.parameters, ceilings)
    return tool


def _strip_titles(schema: dict[str, Any]) -> None:
    schema.pop("title", None)
    for argument in schema.get("properties", {}).values():
        argument.pop("title", None)


def _publish_ceilings(
    arg_model: type[BaseModel], schema: dict[str, Any], ceilings: Mapping[str, int]
) -> None:
    for name, field in arg_model.model_fields.items():
        for marker in field.metadata:
            if not isinstance(marker, ConfiguredCeiling):
                continue
            if marker.setting not in ceilings:
                raise RuntimeError(
                    f"Argument {name} is capped by setting {marker.setting}, "
                    "which the server did not publish"
                )
            argument = schema["properties"][field.alias or name]
            argument["description"] = marker.describe(ceilings[marker.setting])
