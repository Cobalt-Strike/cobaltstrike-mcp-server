"""Command consent policy, independent of configuration and approval transport."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal

from cs_server_mcp import agent_text
from cs_server_mcp.command_errors import CommandSelectionError

Decision = Literal["allow", "ask", "deny"]
ApprovalOutcome = Literal["approved", "declined", "canceled", "unavailable"]
ApprovalRequester = Callable[[str, str], Awaitable[ApprovalOutcome]]


GROUP_RULE_PREFIX = "group:"
# Stated in agent_text.APPROVAL_ARGUMENTS_TRUNCATED.
_APPROVAL_ARGUMENTS_MAX_CHARS = 2_000


@dataclass(frozen=True)
class CommandRule:
    name: str
    # When true, name is a glob over the command's help groups rather than its name.
    group: bool = False

    def describe(self) -> str:
        return f"{GROUP_RULE_PREFIX}{self.name}" if self.group else self.name


@dataclass(frozen=True)
class CommandPolicy:
    default: Decision = "ask"
    allow: tuple[CommandRule, ...] = ()
    ask: tuple[CommandRule, ...] = ()
    deny: tuple[CommandRule, ...] = ()

    def rules(self) -> Iterator[tuple[Decision, CommandRule]]:
        """Rules in the order the tiers are checked: deny, ask, allow."""
        for tier, rules in (("deny", self.deny), ("ask", self.ask), ("allow", self.allow)):
            for rule in rules:
                yield tier, rule


@dataclass(frozen=True)
class PolicyDecision:
    outcome: Literal["allow", "ask", "deny", "undetermined"]
    rule: str | None


# A message-only form: accepting the prompt is the approval. Codex rejects any other
# top-level key and cancels the prompt unseen.
APPROVAL_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


def evaluate_command_policy(
    policy: CommandPolicy, *, command_name: str, groups: Sequence[str] | None = None
) -> PolicyDecision:
    """Name rules first (any tier), then group rules, then the default.

    ``groups=None`` means the command definition has not been read yet, so a decision
    that a group rule could still change is ``undetermined``.
    """
    for tier, rule in policy.rules():
        if not rule.group and fnmatchcase(command_name, rule.name):
            return PolicyDecision(tier, f"{tier}: {rule.describe()}")
    if groups is None and any(rule.group for _, rule in policy.rules()):
        return PolicyDecision("undetermined", None)
    for tier, rule in policy.rules():
        if rule.group and any(fnmatchcase(group, rule.name) for group in groups or ()):
            return PolicyDecision(tier, f"{tier}: {rule.describe()}")
    return PolicyDecision(policy.default, f"default: {policy.default}")


def parse_rule_text(text: str) -> dict[str, str]:
    if text.startswith(GROUP_RULE_PREFIX):
        return {"group": text.removeprefix(GROUP_RULE_PREFIX)}
    return {"name": text}


def parse_env_rules(value: str) -> list[dict[str, str]]:
    return [parse_rule_text(entry.strip()) for entry in value.split(",") if entry.strip()]


def build_approval_summary(*, command_name: str, arguments: str) -> str:
    shown = arguments[:_APPROVAL_ARGUMENTS_MAX_CHARS]
    truncated = len(arguments) > _APPROVAL_ARGUMENTS_MAX_CHARS
    if not shown:
        shown = agent_text.APPROVAL_ARGUMENTS_NONE
    elif truncated or "\n" in shown or "\r" in shown:
        shown = agent_text.APPROVAL_ARGUMENTS_MULTILINE + shown
    if truncated:
        shown += agent_text.APPROVAL_ARGUMENTS_TRUNCATED
    return agent_text.APPROVAL_SUMMARY.format(command_name=command_name, arguments=shown)


class CommandPolicyError(CommandSelectionError):
    def __init__(self, code: str, message: str, *, rule: str | None, next_step: str):
        super().__init__(code, message, next_step=next_step)
        self.rule = rule


def policy_refusal(
    command_name: str, *, rule: str | None, lookup: bool = False
) -> CommandPolicyError:
    return CommandPolicyError(
        "command_not_permitted",
        agent_text.COMMAND_NOT_PERMITTED.format(command_name=command_name),
        rule=rule,
        next_step=(
            agent_text.COMMAND_NOT_PERMITTED_LOOKUP_NEXT_STEP
            if lookup
            else agent_text.COMMAND_NOT_PERMITTED_NEXT_STEP
        ),
    )


def approval_failure(outcome: ApprovalOutcome, *, rule: str | None) -> CommandPolicyError:
    steps = {
        "declined": agent_text.APPROVAL_DECLINED_NEXT_STEP,
        "canceled": agent_text.APPROVAL_CANCELED_NEXT_STEP,
        "unavailable": agent_text.APPROVAL_UNAVAILABLE_NEXT_STEP,
    }
    return CommandPolicyError(
        agent_text.APPROVAL_FAILURE_CODE.format(outcome=outcome),
        agent_text.APPROVAL_FAILURE_MESSAGE.format(outcome=outcome),
        rule=rule,
        next_step=steps[outcome],
    )
