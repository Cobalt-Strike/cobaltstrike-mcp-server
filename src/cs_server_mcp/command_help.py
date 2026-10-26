"""The help text composed for a command: the console help, the argument layout line for a
verified builtin, and the technique and listener lists the REST API serves on endpoints of
its own."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from cs_server_mcp import agent_text
from cs_server_mcp.client import ClientCall
from cs_server_mcp.resource_views import optional_text
from cs_server_mcp.tool_errors import UPSTREAM_ERRORS

# Builtins whose first argument is a technique, with the client method that lists them.
_TECHNIQUE_COMMANDS: Mapping[str, str] = {
    "jump": "list_jump_techniques",
    "remote-exec": "list_remote_exec_techniques",
    "elevate": "list_elevate_techniques",
    "runasadmin": "list_runasadmin_techniques",
}
_LISTENER_SOURCE = "@listener:"
_PAYLOAD_STORE_SOURCE = "@payload:"


def fold_subcommand_rows(rows: Sequence[Any]) -> list[Any]:
    """Fold ``<command> <subcommand>`` catalog rows into their command.

    The team server lists ``mode dns`` and the like as rows of their own, names with
    whitespace that ``cs_execute_command`` rejects. A row whose command is listed is
    dropped; otherwise a command is synthesized whose help lists the subcommands.
    """
    folded: list[Any] = []
    listed: set[str] = set()
    orphans: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
    for row in rows:
        name = row.get("name") if isinstance(row, Mapping) else None
        tokens = name.split() if isinstance(name, str) else []
        if len(tokens) > 1:
            orphans.setdefault(tokens[0], []).append((" ".join(tokens[1:]), row))
            continue
        folded.append(row)
        if tokens:
            listed.add(tokens[0])
    folded.extend(
        _synthesized_command(parent, subcommands)
        for parent, subcommands in orphans.items()
        if parent not in listed
    )
    return folded


def _synthesized_command(
    parent: str, subcommands: Sequence[tuple[str, Mapping[str, Any]]]
) -> dict[str, Any]:
    groups: list[str] = []
    lines: list[str] = []
    for subcommand, row in subcommands:
        groups.extend(group for group in row.get("groups") or [] if group not in groups)
        lines.append(_subcommand_help_line(f"{parent} {subcommand}", row.get("description")))
    return {
        "name": parent,
        "description": agent_text.COMMAND_SUBCOMMANDS_DESCRIPTION.format(
            names=", ".join(subcommand for subcommand, _ in subcommands)
        ),
        "details": "\n".join(lines),
        "groups": groups,
    }


def _subcommand_help_line(name: str, description: Any) -> str:
    if isinstance(description, str) and description.strip():
        return agent_text.COMMAND_SUBCOMMAND_HELP_LINE.format(name=name, description=description)
    return name


def command_help(command: Mapping[str, Any]) -> Any:
    # Only a builtin gets the layout line: a script alias sharing a builtin's name is
    # encoded as a script command.
    details = command.get("details")
    layout = (
        agent_text.COMMAND_ARGUMENT_LAYOUTS.get(command.get("name"))
        if "builtin" in (command.get("groups") or [])
        else None
    )
    if layout is None:
        return details
    return _with_appendix(details, agent_text.COMMAND_LAYOUT_HELP.format(layout=layout))


def _with_appendix(details: Any, appendix: str) -> str:
    if isinstance(details, str) and details.strip():
        return f"{details.rstrip()}\n\n{appendix}"
    return appendix


def _technique_help_lines(command_name: str, techniques: Sequence[Any]) -> list[str]:
    lines: list[str] = []
    for technique in techniques:
        if not isinstance(technique, Mapping):
            continue
        name = optional_text(technique.get("name"))
        if name is None:
            continue
        lines.append(
            _technique_line(
                name,
                arch=optional_text(technique.get("arch")),
                description=optional_text(technique.get("description")),
            )
        )
    if not lines:
        return [agent_text.COMMAND_TECHNIQUES_NONE.format(command_name=command_name)]
    return [agent_text.COMMAND_TECHNIQUES_HEADER.format(command_name=command_name), *lines]


def _technique_line(name: str, *, arch: str | None, description: str | None) -> str:
    if description is None:
        return f"{name} ({arch})" if arch else name
    if arch:
        return agent_text.COMMAND_TECHNIQUE_LINE_ARCH.format(
            name=name, arch=arch, description=description
        )
    return agent_text.COMMAND_TECHNIQUE_LINE.format(name=name, description=description)


async def _with_technique_help(
    call_cs: ClientCall, beacon_id: str, command: Mapping[str, Any]
) -> dict[str, Any]:
    name = command.get("name")
    if not isinstance(name, str) or name not in _TECHNIQUE_COMMANDS:
        return dict(command)
    try:
        techniques = await call_cs(_TECHNIQUE_COMMANDS[name], beacon_id)
    except UPSTREAM_ERRORS:
        appendix = agent_text.COMMAND_TECHNIQUES_UNAVAILABLE.format(command_name=name)
    else:
        appendix = "\n".join(_technique_help_lines(name, techniques))
    return {**command, "details": _with_appendix(command.get("details"), appendix)}


def _listener_help_lines(listeners: Sequence[Any]) -> list[str]:
    lines: list[str] = []
    for listener in listeners:
        if not isinstance(listener, Mapping):
            continue
        name = optional_text(listener.get("name"))
        if name is None:
            continue
        payload = optional_text(listener.get("payload"))
        line = (
            agent_text.COMMAND_LISTENER_LINE.format(name=name, payload=payload) if payload else name
        )
        error = optional_text(listener.get("error"))
        if error:
            line += agent_text.COMMAND_LISTENER_ERROR.format(error=error)
        lines.append(line)
    if not lines:
        return [agent_text.COMMAND_LISTENERS_NONE]
    return [agent_text.COMMAND_LISTENERS_HEADER, *lines]


async def _with_payload_source_help(
    call_cs: ClientCall, command: Mapping[str, Any]
) -> dict[str, Any]:
    details = command.get("details")
    if not isinstance(details, str) or _PAYLOAD_STORE_SOURCE not in details:
        return dict(command)
    if _LISTENER_SOURCE in details:
        try:
            listeners = await call_cs("list_listeners")
        except UPSTREAM_ERRORS:
            lines = [agent_text.COMMAND_LISTENERS_UNAVAILABLE]
        else:
            lines = _listener_help_lines(listeners)
        lines.append(agent_text.COMMAND_PAYLOAD_STORE_NOTE)
    else:
        lines = [agent_text.COMMAND_PAYLOAD_STORE_SHELLCODE_NOTE]
    return {**command, "details": _with_appendix(details, "\n".join(lines))}


async def with_help_appendices(
    call_cs: ClientCall, beacon_id: str, command: Mapping[str, Any]
) -> dict[str, Any]:
    command = await _with_technique_help(call_cs, beacon_id, command)
    return await _with_payload_source_help(call_cs, command)
