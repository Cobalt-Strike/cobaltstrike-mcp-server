"""Credential tools through MCP validation, response shaping, and error handling."""

from __future__ import annotations

from typing import Any

import pytest

from cs_server_mcp.output_contracts import CredentialListPage, CredentialReceipt, CredentialRecord
from tests.fake_teamserver import FakeTeamServer, api_error
from tests.harness import PROTOCOL_MODES, connect, contract, error_payload, make_settings


@pytest.mark.parametrize("mode", PROTOCOL_MODES)
async def test_empty_credential_store_is_an_empty_page(teamserver: FakeTeamServer, mode) -> None:
    async with connect(make_settings(), teamserver, mode=mode) as mcp:
        page = contract(await mcp.call("cs_list_credentials"), CredentialListPage)

    assert page.results == []
    assert page.total_records == 0
    assert page.has_more is False
    assert page.next_offset is None


async def test_credentials_keep_ids_values_and_metadata_and_page_in_id_order(
    teamserver: FakeTeamServer,
) -> None:
    for credential_id in ("10", "2", "1"):
        teamserver.add_stored_credential(
            credential_id,
            username="alice",
            secret="  test secret\n",
            realm="EXAMPLE",
            secret_type="plaintext",
            host="WS01",
            source="operator",
            note="test account",
            created="2026-11-16T12:00:00Z",
        )
    async with connect(make_settings(), teamserver) as mcp:
        first = contract(await mcp.call("cs_list_credentials", limit=2), CredentialListPage)
        last = contract(
            await mcp.call("cs_list_credentials", limit=2, offset=first.next_offset),
            CredentialListPage,
        )

    assert first.total_records == 3
    assert first.has_more is True
    assert first.next_offset == 2
    assert [row.credential_id for row in first.results + last.results] == ["1", "2", "10"]
    assert last.has_more is False
    assert last.next_offset is None
    assert first.results[0].model_dump() == {
        "credential_id": "1",
        "username": "alice",
        "secret": "  test secret\n",
        "realm": "EXAMPLE",
        "secret_type": "plaintext",
        "host": "WS01",
        "source": "operator",
        "note": "test account",
        "created_at": "2026-11-16T12:00:00Z",
    }


@pytest.mark.parametrize("field", ["user", "realm", "secret_type", "host", "source", "note"])
async def test_credential_search_filters_metadata_before_paging(
    teamserver: FakeTeamServer, field: str
) -> None:
    teamserver.add_stored_credential("1", **{field: "MATCH-ME"})
    teamserver.add_stored_credential("2", secret="MATCH-ME")
    async with connect(make_settings(), teamserver) as mcp:
        page = contract(
            await mcp.call("cs_list_credentials", search_regex="(?i)match-me", limit=1),
            CredentialListPage,
        )

    assert [row.credential_id for row in page.results] == ["1"]
    assert page.total_records == 1
    assert page.next_offset is None


async def test_credential_lookup_ignores_search_and_paging(teamserver: FakeTeamServer) -> None:
    teamserver.add_stored_credential("10", secret="exact value")
    async with connect(make_settings(), teamserver) as mcp:
        row = contract(
            await mcp.call("cs_list_credentials", credential_id="10", search_regex="[", offset=100),
            CredentialRecord,
        )
    assert row.credential_id == "10"
    assert row.secret == "exact value"
    assert row.realm is None


async def test_credential_lists_clamp_the_limit(teamserver: FakeTeamServer) -> None:
    for credential_id in range(51):
        teamserver.add_stored_credential(str(credential_id))
    async with connect(make_settings(), teamserver) as mcp:
        page = contract(await mcp.call("cs_list_credentials", limit=100), CredentialListPage)
    assert len(page.results) == page.limit_clamped_to == 50
    assert page.next_offset == 50


@pytest.mark.parametrize("mode", PROTOCOL_MODES)
@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {
            "realm": "EXAMPLE",
            "secret_type": "plaintext",
            "host": "WS01",
            "source": "operator",
            "note": "test",
        },
    ],
)
async def test_add_credential_preserves_values_and_can_be_listed(
    teamserver: FakeTeamServer, mode, metadata: dict[str, str]
) -> None:
    async with connect(make_settings(), teamserver, mode=mode) as mcp:
        receipt = contract(
            await mcp.call(
                "cs_add_credential", username="alice", secret="  test secret\n", **metadata
            ),
            CredentialReceipt,
        )
        page = contract(await mcp.call("cs_list_credentials"), CredentialListPage)

    assert receipt.store_outcome == "accepted"
    assert "cs_list_credentials" in receipt.next_step
    [row] = page.results
    assert row.username == "alice"
    assert row.secret == "  test secret\n"
    for field, value in metadata.items():
        assert getattr(row, field) == value
    assert len(teamserver.credential_writes) == 1
    assert teamserver.submissions == []


@pytest.mark.parametrize("arguments", [{"username": ""}, {"secret": ""}, {"user": "alice"}])
async def test_invalid_credential_arguments_do_not_write(
    teamserver: FakeTeamServer, arguments: dict[str, Any]
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        error = error_payload(
            await mcp.call(
                "cs_add_credential", **{"username": "alice", "secret": "test", **arguments}
            )
        )
    assert error["store_outcome"] == "not_submitted"
    assert error["error"]["code"] == "invalid_argument"
    assert teamserver.credential_writes == []


@pytest.mark.parametrize(
    ("failure", "outcome"),
    [(api_error(403), "rejected"), (api_error(500), "uncertain"), (TimeoutError(), "uncertain")],
)
async def test_failed_credential_writes_report_the_outcome_without_retrying(
    teamserver: FakeTeamServer, failure: Exception, outcome: str
) -> None:
    teamserver.fail("add_credential", failure)
    async with connect(make_settings(), teamserver) as mcp:
        error = error_payload(await mcp.call("cs_add_credential", username="alice", secret="test"))
    assert error["store_outcome"] == outcome
    assert error["next_step"]
    if outcome == "uncertain":
        assert "cs_list_credentials" in error["next_step"]
    assert len(teamserver.credential_writes) == 1
    assert teamserver.credentials == {}


async def test_missing_credential_names_the_lookup_and_recovery_tool(
    teamserver: FakeTeamServer,
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        error = error_payload(await mcp.call("cs_list_credentials", credential_id="missing"))
    assert error["error"]["code"] == "not_found"
    assert error["request"] == {"credential_id": "missing"}
    assert "cs_list_credentials" in error["next_step"]


@pytest.mark.parametrize("credential_id", ["", ".", "..", " "])
async def test_invalid_credential_identifiers_fail_locally(
    teamserver: FakeTeamServer, credential_id: str
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        error = error_payload(await mcp.call("cs_list_credentials", credential_id=credential_id))
    assert error["error"]["code"] == "invalid_argument"


async def test_credential_response_shaping_preserves_the_secret_and_identity(
    teamserver: FakeTeamServer,
) -> None:
    secret = "long secret " * 600
    teamserver.add_stored_credential("1", secret=secret, note="long note " * 1000)
    async with connect(make_settings(max_response_chars=5_000), teamserver) as mcp:
        listing = contract(await mcp.call("cs_list_credentials"), CredentialListPage)
        lookup = contract(
            await mcp.call("cs_list_credentials", credential_id="1"), CredentialRecord
        )
    assert listing.results[0].secret == lookup.secret == secret
    assert listing.results[0].username == lookup.username == "alice"
    assert listing.results[0].credential_id == lookup.credential_id == "1"
    assert listing.truncation["exceeds_ceiling"] is True
