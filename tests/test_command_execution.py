from __future__ import annotations

import pytest

from cs_server_mcp.command_policy import CommandPolicy, CommandRule
from cs_server_mcp.output_contracts import ExecutionReceipt
from tests.fake_teamserver import FakeTeamServer, api_error
from tests.harness import (
    PROTOCOL_MODES,
    ApprovalPrompts,
    connect,
    contract,
    error_payload,
    make_settings,
    plain_text,
)
from tests.virtual_time import VirtualClock

ASK_SHELL = CommandPolicy(default="deny", ask=(CommandRule("shell"),))


def seed_shell_beacon(teamserver: FakeTeamServer, *, sleep_seconds: int = 5) -> None:
    teamserver.add_beacon("1234", sleep_seconds=sleep_seconds)
    teamserver.add_command("shell")


async def test_execute_command_allowed_by_name_rule_submits_without_prompt(
    teamserver: FakeTeamServer,
) -> None:
    seed_shell_beacon(teamserver)
    teamserver.add_command("netuse_add", groups=["userdefined"])
    policy = CommandPolicy(default="ask", allow=(CommandRule("shell"), CommandRule("netuse_add")))

    async with connect(make_settings(command_policy=policy), teamserver) as mcp:
        result = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="shell",
            command_arguments=["whoami", "/all"],
        )
        # netuse_add <share> "" "" uses the current token: an empty item must stay encodable.
        script = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="netuse_add",
            command_arguments=["\\\\dc\\IPC$", "", "", "/PERSIST"],
        )

    contract(result, ExecutionReceipt)
    contract(script, ExecutionReceipt)
    assert script.structured_content["command_arguments"] == '\\\\dc\\IPC$ "" "" /PERSIST'
    assert result.structured_content == {
        "submission_outcome": "accepted",
        "command_execution_id": "1-1234",
        "command_name": "shell",
        "command_arguments": "whoami /all",
        "submitted_arguments": ["whoami", "/all"],
        "beacon_id": "1234",
        "execution_status": "in_progress",
        "execution_status_message": None,
        "execution_status_note": None,
        "submitted_at": "2026-10-22T12:00:00Z",
        "_truncation": None,
    }
    assert teamserver.submissions == [
        {"beacon_id": "1234", "command": "shell", "arguments": "whoami /all"},
        {"beacon_id": "1234", "command": "netuse_add", "arguments": '\\\\dc\\IPC$ "" "" /PERSIST'},
    ]


@pytest.mark.parametrize("mode", PROTOCOL_MODES)
async def test_execute_command_ask_rule_submits_once_the_user_approves(
    teamserver: FakeTeamServer, mode: str
) -> None:
    seed_shell_beacon(teamserver)
    prompts = ApprovalPrompts("accept")

    async with connect(
        make_settings(command_policy=ASK_SHELL), teamserver, mode=mode, prompts=prompts
    ) as mcp:
        result = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="shell",
            command_arguments=["dir", "C:\\Users"],
        )

    receipt = contract(result, ExecutionReceipt)
    assert prompts.messages == ["Command:   shell\nArguments: dir C:\\Users"]
    assert receipt.submission_outcome == "accepted"
    assert receipt.command_execution_id == "1-1234"
    assert teamserver.submissions == [
        {"beacon_id": "1234", "command": "shell", "arguments": "dir C:\\Users"}
    ]


async def test_execute_command_ask_rule_declined_reports_not_submitted(
    teamserver: FakeTeamServer,
) -> None:
    seed_shell_beacon(teamserver)
    prompts = ApprovalPrompts("decline")

    async with connect(make_settings(command_policy=ASK_SHELL), teamserver, prompts=prompts) as mcp:
        result = await mcp.call(
            "cs_execute_command", beacon_id="1234", command_name="shell", command_arguments=["dir"]
        )

    assert error_payload(result) == {
        "submission_outcome": "not_submitted",
        "error": {
            "code": "approval_declined",
            "message": "Command approval declined",
            "http_status": None,
            "rule": "ask: shell",
        },
        "tool": "cs_execute_command",
        "request": {"beacon_id": "1234", "command_name": "shell"},
        "truncated_arguments": [],
        "next_step": "The user declined. Do not resubmit unless the user asks again.",
    }
    assert prompts.messages == ["Command:   shell\nArguments: dir"]
    assert teamserver.submissions == []


async def test_execute_command_ask_rule_without_elicitation_reports_approval_unavailable(
    teamserver: FakeTeamServer,
) -> None:
    seed_shell_beacon(teamserver)

    async with connect(make_settings(command_policy=ASK_SHELL), teamserver) as mcp:
        result = await mcp.call(
            "cs_execute_command", beacon_id="1234", command_name="shell", command_arguments=["dir"]
        )

    payload = error_payload(result)
    assert payload["submission_outcome"] == "not_submitted"
    assert payload["error"] == {
        "code": "approval_unavailable",
        "message": "Command approval unavailable",
        "http_status": None,
        "rule": "ask: shell",
    }
    assert payload["next_step"] == (
        "This MCP client cannot show approval prompts, so commands that need approval cannot "
        "run from it. Do not send the same command line through another command. Tell the "
        "user; they can use a client with MCP elicitation or list the command under "
        "commands.allow in the MCP server config."
    )
    assert teamserver.submissions == []


async def test_execute_command_denied_by_name_rule_is_refused_before_cobalt_strike_is_asked(
    teamserver: FakeTeamServer,
) -> None:
    # Nothing is seeded: any lookup before the refusal would answer not_found instead.
    policy = CommandPolicy(default="allow", deny=(CommandRule("shell"),))

    async with connect(make_settings(command_policy=policy), teamserver) as mcp:
        result = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="shell",
            command_arguments=["whoami"],
        )

    assert error_payload(result) == {
        "submission_outcome": "not_submitted",
        "error": {
            "code": "command_not_permitted",
            "message": "Command 'shell' is not permitted by the MCP command policy",
            "http_status": None,
            "rule": "deny: shell",
        },
        "tool": "cs_execute_command",
        "request": {"beacon_id": "1234", "command_name": "shell"},
        "truncated_arguments": [],
        "next_step": (
            "This refusal is final: do not resubmit the command or send the same command line "
            "through another command. Commands cs_list_commands lists stay available."
        ),
    }
    assert teamserver.submissions == []


async def test_execute_command_denied_by_group_rule_is_refused_after_the_help_lookup(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_beacon("1234")
    teamserver.add_command("mimikatz", groups=["builtin", "postexdll"])
    policy = CommandPolicy(default="allow", deny=(CommandRule("postexdll", group=True),))

    async with connect(make_settings(command_policy=policy), teamserver) as mcp:
        result = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="mimikatz",
            command_arguments=["sekurlsa::logonpasswords"],
        )

    payload = error_payload(result)
    assert payload["submission_outcome"] == "not_submitted"
    assert payload["error"] == {
        "code": "command_not_permitted",
        "message": "Command 'mimikatz' is not permitted by the MCP command policy",
        "http_status": None,
        "rule": "deny: group:postexdll",
    }
    assert teamserver.submissions == []


async def test_read_command_output_late_answer_arrives_within_one_read(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    seed_shell_beacon(teamserver, sleep_seconds=5)

    async with connect(make_settings(output_wait_seconds=30), teamserver) as mcp:
        receipt = contract(
            await mcp.call(
                "cs_execute_command",
                beacon_id="1234",
                command_name="shell",
                command_arguments=["whoami"],
            ),
            ExecutionReceipt,
        )
        # The beacon answers a second after its check-in falls due, while the read waits.
        teamserver.beacon_answers(
            receipt.command_execution_id, at=clock.after(6), output="DESKTOP-7\\alice\r\n"
        )
        started = clock.elapsed()
        result = await mcp.call(
            "cs_read_command_output", command_execution_id=receipt.command_execution_id
        )

    assert plain_text(result) == "[*] Tasked beacon to run: shell whoami\nDESKTOP-7\\alice"
    waited = clock.elapsed() - started
    assert 6 <= waited < 8, (
        f"waited {waited}s: the read returns once the answer lands, before the forecast deadline"
    )


async def test_read_command_output_silent_beacon_stops_waiting_at_forecast_deadline(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    seed_shell_beacon(teamserver, sleep_seconds=5)

    async with connect(make_settings(output_wait_seconds=30), teamserver) as mcp:
        receipt = contract(
            await mcp.call(
                "cs_execute_command",
                beacon_id="1234",
                command_name="shell",
                command_arguments=["whoami"],
            ),
            ExecutionReceipt,
        )
        started = clock.elapsed()
        result = await mcp.call(
            "cs_read_command_output", command_execution_id=receipt.command_execution_id
        )

    assert plain_text(result) == (
        "[*] Tasked beacon to run: shell whoami\n"
        "[Task status: in_progress. The beacon is overdue: its last check-in was "
        "2026-10-22T12:00:00Z on a 5s sleep. A beacon running a task cannot check in until it "
        "finishes, so it may only be busy. Read again shortly, and check "
        "cs_list_beacons(beacon_id='1234') if it stays overdue.]"
    )
    waited = clock.elapsed() - started
    assert 5 <= waited <= 8, (
        f"waited {waited}s: the read waits for the due check-in plus the margin for its "
        "answer, never the whole 30 s cap"
    )


async def test_read_command_output_checkin_beyond_wait_ceiling_returns_forecast_at_once(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    # A 10 s sleep puts the next check-in (plus its margin) past a 5 s wait ceiling.
    seed_shell_beacon(teamserver, sleep_seconds=10)

    async with connect(make_settings(output_wait_seconds=5), teamserver) as mcp:
        receipt = contract(
            await mcp.call(
                "cs_execute_command",
                beacon_id="1234",
                command_name="shell",
                command_arguments=["whoami"],
            ),
            ExecutionReceipt,
        )
        started = clock.elapsed()
        result = await mcp.call(
            "cs_read_command_output", command_execution_id=receipt.command_execution_id
        )

    assert plain_text(result) == (
        "[*] Tasked beacon to run: shell whoami\n"
        "[Task status: in_progress. The beacon's next check-in is expected by "
        "2026-10-22T12:00:10Z (sleep 10s; last check-in 2026-10-22T12:00:00Z).]"
    )
    assert clock.elapsed() == started, "a check-in beyond the ceiling is not waited for"


async def test_execute_command_on_dead_beacon_warns_in_receipt_and_read_does_not_wait(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234", alive=False, sleep_seconds=5, last_checkin=clock.after(-900))
    teamserver.add_command("shell")

    async with connect(make_settings(output_wait_seconds=30), teamserver) as mcp:
        receipt = contract(
            await mcp.call(
                "cs_execute_command",
                beacon_id="1234",
                command_name="shell",
                command_arguments=["whoami"],
            ),
            ExecutionReceipt,
        )
        started = clock.elapsed()
        read_result = await mcp.call(
            "cs_read_command_output", command_execution_id=receipt.command_execution_id
        )

    assert receipt.submission_outcome == "accepted"
    assert receipt.execution_status == "in_progress"
    assert receipt.execution_status_note == (
        "Beacon 1234 is marked dead (last check-in 900s ago), so this task waits for a "
        "check-in that may never come. Check cs_list_beacons(beacon_id='1234') before polling."
    )
    assert plain_text(read_result) == (
        "[*] Tasked beacon to run: shell whoami\n"
        "[Task status: in_progress. Beacon 1234 is marked dead (last check-in 900s ago), so "
        "output may never arrive. Check cs_list_beacons(beacon_id='1234') before reading "
        "again.]"
    )
    assert clock.elapsed() == started, "a dead beacon's check-in is not waited for"


async def test_execute_command_upstream_failure_reports_uncertain_submission(
    teamserver: FakeTeamServer,
) -> None:
    seed_shell_beacon(teamserver)
    teamserver.fail("execute_console_command", api_error(500, "console busy"))

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call(
            "cs_execute_command",
            beacon_id="1234",
            command_name="shell",
            command_arguments=["whoami"],
        )

    assert error_payload(result) == {
        "submission_outcome": "uncertain",
        "error": {
            "code": "upstream_error",
            "message": "Cobalt Strike request failed: HTTP 500 Internal Server Error: console busy",
            "http_status": 500,
        },
        "tool": "cs_execute_command",
        "request": {"beacon_id": "1234", "command_name": "shell"},
        "truncated_arguments": [],
        "next_step": (
            "Check command execution history with cs_list_command_executions for the beacon; "
            "if a matching execution exists, read it with cs_read_command_output instead of "
            "resubmitting."
        ),
    }
