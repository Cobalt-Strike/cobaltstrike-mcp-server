from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from cs_server_mcp.command_policy import CommandPolicy, CommandRule
from cs_server_mcp.output_contracts import (
    ArtifactListPage,
    ArtifactUploadLink,
    Beacons,
    CommandCatalog,
    Downloads,
    DownloadTransfer,
    ExecutionHistory,
    Screenshots,
    ScreenshotTransfer,
)
from cs_server_mcp.server import TRANSFER_LINK_TTL_SECONDS
from tests.fake_teamserver import C2_PROFILE, PNG_BYTES, SYSTEM_INFORMATION, FakeTeamServer
from tests.harness import connect, contract, error_payload, make_settings, plain_text
from tests.virtual_time import VirtualClock

SECRET_BYTES = b"top secret\n"
SECRET_SHA256 = "492cb4e5121e0c160628ff636e10c0614240e540e90fcf52be576a76b433e4b4"
PNG_SHA256 = "8c6806d8d6093084661ba908761d0bc076628c282907d140abe683606d5c0fdd"
LINK_PREFIX = "http://127.0.0.1:50051/mcp/files/"
HOSTS_TEXT = b"10.0.0.5 dc1\n"
HOSTS_SHA256 = "0a2ce43b80c5c82186429402f7793b38ed7601f26774fc806a9a216fce765b20"
NEW_LINK = "Call cs_upload_artifact again for a new link."


async def test_list_beacons_default_listing_lists_live_beacons_by_numeric_id(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234", hostname="WS01", username="alice")
    teamserver.add_beacon("567", hostname="DC01", username="bob")
    teamserver.add_beacon("89", hostname="OLD01", alive=False, last_checkin=clock.after(-3600))

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_list_beacons")

    page = contract(result, Beacons).root
    assert [row.beacon_id for row in page.results] == ["567", "1234"], page
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 2)
    assert result.structured_content["results"][1] == {
        "beacon_id": "1234",
        "parent_beacon_id": None,
        "hostname": "WS01",
        "username": "alice",
        "is_admin": False,
        "process_name": "explorer.exe",
        "process_id": 4242,
        "listener": "https-main",
        "alive": True,
        "last_seen_at": "2026-10-22T12:00:00Z",
        "last_checkin_age": "0s",
        "note": "",
    }


async def test_list_commands_global_catalog_lists_permitted_commands_without_help(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_command("shell", description="Execute a command via cmd.exe")
    teamserver.add_command("bof-ls", groups=["userdefined"], description="List a directory")
    teamserver.add_command("exit", description="Terminate the beacon session")
    teamserver.add_command("clear", description="Clear the beacon queue")
    policy = CommandPolicy(default="allow", deny=(CommandRule("exit"),))

    async with connect(make_settings(command_policy=policy), teamserver) as mcp:
        result = await mcp.call("cs_list_commands")

    page = contract(result, CommandCatalog)
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 2)
    assert result.structured_content["results"] == [
        {"command_name": "bof-ls", "description": "List a directory"},
        {"command_name": "shell", "description": "Execute a command via cmd.exe"},
    ]


async def test_list_command_executions_beacon_history_lists_newest_first_with_detail_counts(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234")
    teamserver.add_task(
        "a1-1234",
        bid="1234",
        command_line="pwd",
        output="C:\\Users\\alice",
        created=clock.after(-120),
        user="neo",
    )
    teamserver.add_task(
        "b2-1234",
        bid="1234",
        command_line="ls C:\\secret",
        status="FAILED",
        errors=["could not open C:\\secret"],
        created=clock.after(-60),
        updated=clock.after(-50),
        user="trinity",
    )

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_list_command_executions", beacon_id="1234")

    page = contract(result, ExecutionHistory).root
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 2)
    assert page.execution_status_note is None
    assert result.structured_content["results"] == [
        {
            "command_execution_id": "b2-1234",
            "execution_status": "failed",
            "execution_status_message": "could not open C:\\secret",
            "result_count": 0,
            "error_count": 1,
            "command_name": "ls",
            "command_arguments": "C:\\secret",
            "beacon_id": "1234",
            "requested_by": "trinity",
            "submitted_at": "2026-10-22T11:59:00Z",
            "updated_at": "2026-10-22T11:59:10Z",
            "job_id": None,
        },
        {
            "command_execution_id": "a1-1234",
            "execution_status": "completed",
            "execution_status_message": None,
            "result_count": 1,
            "error_count": 0,
            "command_name": "pwd",
            "command_arguments": "",
            "beacon_id": "1234",
            "requested_by": "neo",
            "submitted_at": "2026-10-22T11:58:00Z",
            "updated_at": None,
            "job_id": None,
        },
    ]


async def test_read_command_output_completed_task_renders_acknowledgement_lines_and_notices(
    teamserver: FakeTeamServer,
) -> None:
    task = teamserver.add_task(
        "c3-1234",
        bid="1234",
        command_line="ls C:\\",
        status="COMPLETED",
        output="file.txt\r\nnotes.md\r\n",
        errors=["access denied to C:\\locked", "[-] Bind Failed with error: 82\n"],
    )
    task["taskAcknowledgements"] = [{"text": "Tasked beacon to list C:\\", "tactics": []}]

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_read_command_output", command_execution_id="c3-1234")

    assert plain_text(result) == (
        "[*] Tasked beacon to list C:\\\n"
        "file.txt\n"
        "notes.md\n"
        "[-] access denied to C:\\locked\n"
        "[-] Bind Failed with error: 82\n"
        "[Task status: completed]\n"
        "[Errors reported: 2]"
    )


async def test_list_artifacts_lists_artifact_references_with_the_sizes_of_their_files(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    teamserver.add_artifact("@artifacts/tools/Rubeus.exe")
    teamserver.add_artifact("@artifacts/beacon.dll")
    teamserver.add_artifact("@artifacts/missing.bin")
    teamserver.add_artifact("@scripts/helper.cna", key="scripts/helper.cna")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "Rubeus.exe").write_bytes(b"MZ" * 100)
    (tmp_path / "beacon.dll").write_bytes(b"MZ")

    async with connect(make_settings(artifacts_directory=tmp_path), teamserver) as mcp:
        result = await mcp.call("cs_list_artifacts")

    page = contract(result, ArtifactListPage)
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 3)
    assert result.structured_content["results"] == [
        {"artifact_reference": "@artifacts/beacon.dll", "size_bytes": 2},
        {"artifact_reference": "@artifacts/missing.bin"},
        {"artifact_reference": "@artifacts/tools/Rubeus.exe", "size_bytes": 200},
    ]


async def test_list_artifacts_searches_references_and_pages_them(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    for name in ("a.exe", "b.exe", "c.dll"):
        teamserver.add_artifact(f"@artifacts/{name}")
        (tmp_path / name).write_bytes(b"x" * len(name))

    async with connect(make_settings(artifacts_directory=tmp_path), teamserver) as mcp:
        searched = await mcp.call("cs_list_artifacts", search_regex=r"\.exe$")
        second = await mcp.call("cs_list_artifacts", limit=2, offset=2)

    assert searched.structured_content["total_records"] == 2
    assert [row["artifact_reference"] for row in searched.structured_content["results"]] == [
        "@artifacts/a.exe",
        "@artifacts/b.exe",
    ]
    assert second.structured_content["has_more"] is False
    assert second.structured_content["results"] == [
        {"artifact_reference": "@artifacts/c.dll", "size_bytes": 5}
    ]


async def test_list_artifacts_reads_no_size_for_a_reference_that_leaves_the_directory(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    directory = tmp_path / "artifacts"
    directory.mkdir()
    (tmp_path / "secret").write_bytes(b"outside")
    (directory / "sub").mkdir()
    teamserver.add_artifact("@artifacts/../secret")
    teamserver.add_artifact("@artifacts/sub")

    async with connect(make_settings(artifacts_directory=directory), teamserver) as mcp:
        result = await mcp.call("cs_list_artifacts")

    assert result.structured_content["results"] == [
        {"artifact_reference": "@artifacts/../secret"},
        {"artifact_reference": "@artifacts/sub"},
    ]


async def test_upload_artifact_link_stores_the_body_in_the_artifacts_directory_once(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    teamserver.add_artifact("@artifacts/hosts.txt")
    directory = tmp_path / "artifacts"
    directory.mkdir()

    async with connect(make_settings(artifacts_directory=directory), teamserver) as mcp:
        link = contract(
            await mcp.call("cs_upload_artifact", artifact_name=" hosts.txt "), ArtifactUploadLink
        )
        async with mcp.http() as http:
            first = await http.put(link.url, content=HOSTS_TEXT)
            second = await http.put(link.url, content=HOSTS_TEXT)

    assert link.url.startswith(LINK_PREFIX), link.url
    assert link.expires_at.endswith("Z"), link.expires_at
    assert link.max_bytes == 4_000_000
    assert first.status_code == 201
    assert first.headers["cache-control"] == "no-store"
    assert first.json() == {
        "artifact_reference": "@artifacts/hosts.txt",
        "size_bytes": len(HOSTS_TEXT),
        "sha256": HOSTS_SHA256,
    }
    assert (directory / "hosts.txt").read_bytes() == HOSTS_TEXT
    assert sorted(directory.iterdir()) == [directory / "hosts.txt"], "no part file is left"
    assert second.status_code == 404, "an upload link stores its file once"
    assert second.json() == {
        "detail": "Unknown, expired, or already used upload link.",
        "next_step": NEW_LINK,
    }


async def test_upload_artifact_link_adds_a_notice_when_the_team_server_does_not_list_the_file(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    async with connect(make_settings(artifacts_directory=tmp_path), teamserver) as mcp:
        link = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        async with mcp.http() as http:
            response = await http.put(link.url, content=HOSTS_TEXT)

    assert response.status_code == 201
    body = response.json()
    assert body["artifact_reference"] == "@artifacts/hosts.txt"
    assert body["notice"].startswith("Cobalt Strike did not list this artifact")
    assert "artifacts.directory" in body["notice"]


async def test_upload_artifact_link_keeps_identical_bytes_and_refuses_different_ones(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    (tmp_path / "hosts.txt").write_bytes(HOSTS_TEXT)

    async with connect(make_settings(artifacts_directory=tmp_path), teamserver) as mcp:
        same = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        different = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        async with mcp.http() as http:
            kept = await http.put(same.url, content=HOSTS_TEXT)
            refused = await http.put(different.url, content=b"10.0.0.9 dc2\n")

    assert kept.status_code == 201
    assert kept.json()["sha256"] == HOSTS_SHA256
    assert refused.status_code == 409
    assert refused.json() == {
        "detail": "An artifact named 'hosts.txt' already exists with different content.",
        "next_step": (
            "Call cs_upload_artifact with another name, or use cs_list_artifacts to inspect the "
            "existing one."
        ),
    }
    assert (tmp_path / "hosts.txt").read_bytes() == HOSTS_TEXT


async def test_upload_artifact_link_refuses_a_body_over_the_cap_and_stores_nothing(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    settings = make_settings(artifacts_directory=tmp_path, max_upload_bytes=8)

    async with connect(settings, teamserver) as mcp:
        link = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        async with mcp.http() as http:
            response = await http.put(link.url, content=b"0123456789")
        pending = len(mcp.uploads)

    assert link.max_bytes == 8
    assert response.status_code == 413
    assert response.json()["detail"] == "The file is 10 bytes; limits.max_upload_bytes allows 8."
    assert response.json()["next_step"].endswith("call cs_upload_artifact again for a new link.")
    assert list(tmp_path.iterdir()) == []
    assert pending == 0


async def test_upload_artifact_link_reports_a_directory_it_cannot_write(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    missing = tmp_path / "missing"

    async with connect(make_settings(artifacts_directory=missing), teamserver) as mcp:
        link = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        async with mcp.http() as http:
            response = await http.put(link.url, content=HOSTS_TEXT)

    assert response.status_code == 500
    assert response.json()["detail"].startswith(f"Could not store the file under {missing}: ")
    assert "artifacts.directory" in response.json()["next_step"]
    assert not missing.exists()


async def test_upload_artifact_link_expires_unused(
    teamserver: FakeTeamServer, tmp_path: Path
) -> None:
    async with connect(make_settings(artifacts_directory=tmp_path), teamserver) as mcp:
        link = contract(
            await mcp.call("cs_upload_artifact", artifact_name="hosts.txt"), ArtifactUploadLink
        )
        await asyncio.sleep(TRANSFER_LINK_TTL_SECONDS + 1)
        async with mcp.http() as http:
            response = await http.put(link.url, content=HOSTS_TEXT)

    assert response.status_code == 404
    assert list(tmp_path.iterdir()) == []


async def test_upload_artifact_refuses_a_path_as_a_name_without_opening_a_link(
    teamserver: FakeTeamServer,
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_upload_artifact", artifact_name="tools/x.txt")
        pending = len(mcp.uploads)

    payload = error_payload(result)
    assert payload["error"]["code"] == "invalid_argument"
    assert "without directories" in payload["error"]["message"]
    assert pending == 0


async def test_list_downloads_lists_active_transfer_before_completed_file_with_host(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234", hostname="WS01")
    teamserver.add_download(
        "7",
        bid="1234",
        name="secrets.txt",
        path="C:\\Users\\alice\\Documents\\",
        data=SECRET_BYTES,
        downloaded_at=clock.after(-300),
    )
    teamserver.add_active_download(
        "1234", name="big.bin", path="C:\\Temp\\", size=4000, received=1000
    )

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_list_downloads")

    page = contract(result, Downloads).root
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 2)
    active, completed = result.structured_content["results"]
    assert active == {
        "download_id": None,
        "transfer_state": "in_progress",
        "beacon_id": "1234",
        "host": "WS01",
        "remote_file_name": "big.bin",
        "remote_directory": "C:\\Temp",
        "size_bytes": 4000,
        "received_bytes": 1000,
        "progress": pytest.approx(0.25),
    }
    assert completed == {
        "download_id": "7",
        "transfer_state": "completed",
        "progress": pytest.approx(1.0),
        "beacon_id": "1234",
        "host": "WS01",
        "remote_file_name": "secrets.txt",
        "remote_directory": "C:\\Users\\alice\\Documents",
        "downloaded_at": "2026-10-22T11:55:00Z",
        "size_bytes": 11,
    }


async def test_fetch_download_stages_file_behind_one_time_link(teamserver: FakeTeamServer) -> None:
    teamserver.add_beacon("1234", hostname="WS01")
    teamserver.add_download(
        "7", bid="1234", name="secrets.txt", path="C:\\Users\\alice\\", data=SECRET_BYTES
    )

    async with connect(make_settings(), teamserver) as mcp:
        transfer = contract(await mcp.call("cs_fetch_download", download_id="7"), DownloadTransfer)
        async with mcp.http() as http:
            first = await http.get(transfer.url)
            second = await http.get(transfer.url)

    assert transfer.url.startswith(LINK_PREFIX), transfer.url
    assert transfer.expires_at.endswith("Z"), transfer.expires_at
    assert transfer.model_dump(exclude={"url", "expires_at"}) == {
        "size_bytes": 11,
        "sha256": SECRET_SHA256,
        "source_filename": "secrets.txt",
        "download_id": "7",
        "transfer_state": "completed",
        "beacon_id": "1234",
        "remote_file_name": "secrets.txt",
        "remote_directory": "C:\\Users\\alice",
        "host": "WS01",
    }
    assert (first.status_code, first.content) == (200, SECRET_BYTES)
    assert first.headers["content-disposition"] == 'attachment; filename="secrets.txt"'
    assert first.headers["cache-control"] == "no-store"
    assert second.status_code == 404, "a transfer link serves its file once"


async def test_list_screenshots_beacon_filter_lists_that_beacon_captures(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234", hostname="WS01", username="alice")
    teamserver.add_beacon("99", hostname="DC01", username="bob")
    teamserver.add_screenshot("9", bid="1234", title="Downloads", created_at=clock.after(-30))
    teamserver.add_screenshot("10", bid="99", title="Outlook", created_at=clock.after(-20))

    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_list_screenshots", beacon_id="99")

    page = contract(result, Screenshots).root
    assert (page.has_more, page.next_offset, page.total_records) == (False, None, 1)
    assert result.structured_content["results"] == [
        {
            "screenshot_id": "10",
            "beacon_id": "99",
            "hostname": "DC01",
            "username": "bob",
            "window_title": "Outlook",
            "created_at": "2026-10-22T11:59:40Z",
        }
    ]


async def test_fetch_screenshot_stages_png_named_by_capture_time_and_window(
    teamserver: FakeTeamServer, clock: VirtualClock
) -> None:
    teamserver.add_beacon("1234")
    teamserver.add_screenshot("9", bid="1234", title="Downloads", created_at=clock.after(-30))

    async with connect(make_settings(), teamserver) as mcp:
        transfer = contract(
            await mcp.call("cs_fetch_screenshot", screenshot_id="9"), ScreenshotTransfer
        )
        async with mcp.http() as http:
            fetched = await http.get(transfer.url)

    assert transfer.url.startswith(LINK_PREFIX), transfer.url
    assert transfer.model_dump(exclude={"url", "expires_at"}) == {
        "size_bytes": 72,
        "sha256": PNG_SHA256,
        "screenshot_id": "9",
        "beacon_id": "1234",
        "created_at": "2026-10-22T11:59:30Z",
    }
    assert (fetched.status_code, fetched.content) == (200, PNG_BYTES)
    assert fetched.headers["content-type"] == "image/png"
    assert (
        fetched.headers["content-disposition"]
        == 'attachment; filename="screenshot-20261022T115930Z-Downloads.png"'
    )


async def test_fetch_download_link_expires_and_the_staged_file_is_removed(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_beacon("1234")
    teamserver.add_download("7", bid="1234", name="secrets.txt", path="C:\\", data=SECRET_BYTES)

    async with connect(make_settings(), teamserver) as mcp:
        transfer = contract(await mcp.call("cs_fetch_download", download_id="7"), DownloadTransfer)
        [staged_path] = list(mcp.staging.directory.iterdir())
        await asyncio.sleep(TRANSFER_LINK_TTL_SECONDS + 1)
        async with mcp.http() as http:
            fetched = await http.get(transfer.url)

    assert fetched.status_code == 404
    assert not staged_path.exists(), "an expired file is removed from the staging directory"


async def test_get_team_server_reads_every_setting_or_one_and_omits_an_empty_one(
    teamserver: FakeTeamServer,
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        everything = await mcp.call("cs_get_team_server")
        profile = await mcp.call("cs_get_team_server", section="c2_profile")
        teamserver.kill_date = ""
        without_kill_date = await mcp.call("cs_get_team_server")

    assert plain_text(everything) == (
        "teamserver_ip: 10.0.0.1\nkill_date: 2026-12-31\n\n"
        f"[c2_profile]\n{C2_PROFILE}\n\n[system_information]\n{SYSTEM_INFORMATION}"
    )
    assert plain_text(profile) == C2_PROFILE
    assert plain_text(without_kill_date).startswith("teamserver_ip: 10.0.0.1\n\n[c2_profile]\n")
