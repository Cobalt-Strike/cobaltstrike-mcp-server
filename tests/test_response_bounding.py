from __future__ import annotations

import pydantic_core

from cs_server_mcp import agent_text
from cs_server_mcp.output_contracts import Beacons
from tests.fake_teamserver import FakeTeamServer
from tests.harness import connect, contract, make_settings, plain_text

CEILING = 5000


def rendered_chars(payload: object) -> int:
    return len(pydantic_core.to_json(payload, indent=2).decode())


async def test_list_beacons_over_ceiling_cuts_at_a_row_and_continues_by_next_offset(
    teamserver: FakeTeamServer,
) -> None:
    for number in range(1001, 1061):
        teamserver.add_beacon(str(number), hostname=f"WS{number - 1000:02d}")
    async with connect(make_settings(max_response_chars=CEILING), teamserver) as mcp:
        first = await mcp.call("cs_list_beacons", limit=50)
        first_page = first.structured_content
        second = await mcp.call("cs_list_beacons", limit=50, offset=first_page["next_offset"])

    contract(first, Beacons)
    assert rendered_chars(first_page) <= CEILING
    assert [row["beacon_id"] for row in first_page["results"]] == [
        "1001", "1002", "1003", "1004", "1005", "1006",
        "1007", "1008", "1009", "1010", "1011", "1012",
    ]  # fmt: skip
    assert first_page["has_more"] is True
    assert first_page["next_offset"] == 12
    assert first_page["total_records"] == 60
    truncation = first_page["_truncation"]
    assert truncation["truncated"] is True
    assert truncation["reason"] == "max_response_chars"
    assert truncation["max_response_chars"] == CEILING
    assert truncation["response_chars"] > CEILING
    assert truncation["omitted_items"] == 38
    assert truncation["next_step"] == agent_text.LISTING_SPLIT_NEXT_STEP
    second_page = second.structured_content
    assert second_page["results"][0]["beacon_id"] == "1013"
    assert second_page["next_offset"] == 24


async def test_list_beacons_lone_oversized_row_is_kept_with_its_note_shortened(
    teamserver: FakeTeamServer,
) -> None:
    note = "".join(f"{number:04d} " for number in range(1800))  # 9,000 characters
    teamserver.add_beacon("1234", note=note)
    async with connect(make_settings(max_response_chars=CEILING), teamserver) as mcp:
        result = await mcp.call("cs_list_beacons")

    page = contract(result, Beacons).root
    payload = result.structured_content
    assert rendered_chars(payload) <= CEILING
    [row] = payload["results"]
    truncation = payload["_truncation"]
    assert truncation["field_char_limit"] == 3000
    assert row["note"] == note[:3000]
    assert row["beacon_id"] == "1234"
    assert truncation["fields"] == ["results[0].note"]
    assert truncation["omitted_chars"] == 6000
    assert "omitted_items" not in truncation
    assert truncation["next_step"] == agent_text.LISTING_LONE_ROW_SHORTENED
    assert page.has_more is False
    assert page.next_offset is None


async def test_read_command_output_over_the_char_ceiling_keeps_whole_lines_and_names_the_next(
    teamserver: FakeTeamServer,
) -> None:
    # 200 lines of exactly 100 characters.
    teamserver.add_task(
        "1b-1234",
        bid="1234",
        command_line="shell type wide.log",
        output="\n".join(f"{number:04d} " + "x" * 95 for number in range(1, 201)),
        acknowledged=False,
    )
    async with connect(make_settings(max_response_chars=CEILING), teamserver) as mcp:
        first = plain_text(await mcp.call("cs_read_command_output", command_execution_id="1b-1234"))
        rest = plain_text(
            await mcp.call("cs_read_command_output", command_execution_id="1b-1234", start_line=49)
        )

    assert len(first) <= CEILING
    first_lines = first.split("\n")
    assert len(first_lines) == 49
    assert first_lines[0] == "0001 " + "x" * 95
    assert first_lines[47] == "0048 " + "x" * 95
    assert first_lines[48] == "[More output available. Read again with start_line=49.]"
    assert rest.split("\n")[0] == "0049 " + "x" * 95


async def test_read_command_output_single_line_over_ceiling_fails_naming_the_line(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_task(
        "1c-1234",
        bid="1234",
        command_line="shell type blob.bin",
        output="y" * 6000,
        acknowledged=False,
    )
    async with connect(make_settings(max_response_chars=CEILING), teamserver) as mcp:
        result = await mcp.call("cs_read_command_output", command_execution_id="1c-1234")

    assert result.is_error is True
    assert result.structured_content is None
    [block] = result.content
    assert block.text == (
        "Error executing tool cs_read_command_output: Output line 1 and required notices exceed "
        "limits.max_response_chars (5000 characters). Reducing max_lines cannot fix a single "
        "oversized line: ask the user to raise limits.max_response_chars in the MCP server "
        "config or to inspect the output in the Cobalt Strike client."
    )


async def test_read_command_output_max_lines_windows_the_output_and_names_the_next_line(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_task(
        "1d-1234",
        bid="1234",
        command_line="shell dir",
        output="line 1\nline 2\nline 3\nline 4\nline 5",
        acknowledged=False,
    )
    async with connect(make_settings(), teamserver) as mcp:
        first = plain_text(
            await mcp.call("cs_read_command_output", command_execution_id="1d-1234", max_lines=2)
        )
        rest = plain_text(
            await mcp.call(
                "cs_read_command_output",
                command_execution_id="1d-1234",
                start_line=3,
                max_lines=2,
            )
        )

    assert first == "line 1\nline 2\n[More output available. Read again with start_line=3.]"
    assert rest == "line 3\nline 4\n[More output available. Read again with start_line=5.]"
