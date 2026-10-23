from __future__ import annotations

from cs_server_mcp.command_policy import (
    CommandPolicy,
    CommandRule,
    PolicyDecision,
    build_approval_summary,
    evaluate_command_policy,
)


def test_evaluate_name_rule_overrides_group_rule_from_a_stricter_tier() -> None:
    policy = CommandPolicy(
        default="ask",
        allow=(CommandRule("mimikatz"),),
        deny=(CommandRule("postexdll", group=True),),
    )

    decision = evaluate_command_policy(policy, command_name="mimikatz", groups=["postexdll"])

    assert decision == PolicyDecision("allow", "allow: mimikatz")


def test_evaluate_same_name_under_deny_and_allow_is_denied() -> None:
    policy = CommandPolicy(
        default="allow", allow=(CommandRule("shell"),), deny=(CommandRule("shell"),)
    )

    decision = evaluate_command_policy(policy, command_name="shell", groups=["builtin"])

    assert decision == PolicyDecision("deny", "deny: shell")


def test_evaluate_name_rule_matches_as_a_glob() -> None:
    policy = CommandPolicy(default="deny", allow=(CommandRule("bof-*"),))

    decision = evaluate_command_policy(policy, command_name="bof-ls", groups=[])

    assert decision == PolicyDecision("allow", "allow: bof-*")


def test_evaluate_name_glob_miss_falls_to_the_default() -> None:
    policy = CommandPolicy(default="deny", allow=(CommandRule("bof-*"),))

    decision = evaluate_command_policy(policy, command_name="bofls", groups=[])

    assert decision == PolicyDecision("deny", "default: deny")


def test_evaluate_group_rule_matches_as_a_glob_over_any_help_group() -> None:
    policy = CommandPolicy(default="allow", deny=(CommandRule("postex*", group=True),))

    decision = evaluate_command_policy(
        policy, command_name="mimikatz", groups=["builtin", "postexdll"]
    )

    assert decision == PolicyDecision("deny", "deny: group:postex*")


def test_evaluate_group_glob_miss_falls_to_the_default() -> None:
    policy = CommandPolicy(default="allow", deny=(CommandRule("postex*", group=True),))

    decision = evaluate_command_policy(policy, command_name="shell", groups=["builtin"])

    assert decision == PolicyDecision("allow", "default: allow")


def test_evaluate_without_groups_is_undetermined_while_a_group_rule_could_apply() -> None:
    policy = CommandPolicy(default="allow", deny=(CommandRule("postexdll", group=True),))

    decision = evaluate_command_policy(policy, command_name="mimikatz")

    assert decision == PolicyDecision("undetermined", None)


def test_evaluate_without_groups_decides_when_only_name_rules_exist() -> None:
    policy = CommandPolicy(default="ask", deny=(CommandRule("exit"),))

    decision = evaluate_command_policy(policy, command_name="shell")

    assert decision == PolicyDecision("ask", "default: ask")


def test_build_approval_summary_truncates_arguments_after_two_thousand_characters() -> None:
    summary = build_approval_summary(command_name="shell", arguments="x" * 2001)

    assert summary == (
        "Command:   shell\nArguments: [multi-line, expand to read all] "
        + "x" * 2000
        + "\n[Arguments truncated after 2,000 characters]"
    )
