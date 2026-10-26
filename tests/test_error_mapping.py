from __future__ import annotations

from tests.fake_teamserver import FakeTeamServer, api_error, connection_failure
from tests.harness import connect, error_payload, make_settings


async def test_list_beacons_http_404_for_an_id_names_the_id_and_the_listing_to_check(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.add_beacon("1234")
    async with connect(make_settings(), teamserver) as mcp:
        payload = error_payload(await mcp.call("cs_list_beacons", beacon_id="9999"))

    assert payload == {
        "error": {
            "code": "not_found",
            "message": (
                "Cobalt Strike request failed: HTTP 404 Not Found: nothing found for beacon_id 9999"
            ),
            "http_status": 404,
        },
        "tool": "cs_list_beacons",
        "request": {"beacon_id": "9999"},
        "truncated_arguments": [],
        "next_step": (
            "Check the identifier, or list the resource to find one that exists. "
            "Check beacon_id against cs_list_beacons() and follow next_offset if needed."
        ),
    }


async def test_list_beacons_connection_failure_reports_transport_error_without_the_host(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.fail("list_beacons", connection_failure())
    async with connect(make_settings(), teamserver) as mcp:
        result = await mcp.call("cs_list_beacons")

    payload = error_payload(result)
    assert payload["error"] == {
        "code": "transport_error",
        "message": "Cobalt Strike did not answer (ClientConnectionError)",
        "http_status": None,
    }
    assert payload["next_step"] == (
        "Retry later, and check the resource first if this call changes it."
    )
    assert "teamserver.example" not in result.content[0].text


async def test_list_beacons_http_500_reports_upstream_error_with_the_team_server_detail(
    teamserver: FakeTeamServer,
) -> None:
    teamserver.fail("list_beacons", api_error(500, "database locked"))
    async with connect(make_settings(), teamserver) as mcp:
        payload = error_payload(await mcp.call("cs_list_beacons"))

    assert payload["error"] == {
        "code": "upstream_error",
        "message": "Cobalt Strike request failed: HTTP 500 Internal Server Error: database locked",
        "http_status": 500,
    }
    assert payload["next_step"] == (
        "Retry later, and check the resource first if this call changes it."
    )


async def test_list_beacons_unknown_argument_is_rejected_by_name_before_any_request(
    teamserver: FakeTeamServer,
) -> None:
    async with connect(make_settings(), teamserver) as mcp:
        payload = error_payload(await mcp.call("cs_list_beacons", limt=5))

    assert payload == {
        "error": {
            "code": "invalid_argument",
            "message": (
                "The arguments do not match the tool's input schema: "
                "limt: Extra inputs are not permitted"
            ),
            "http_status": None,
        },
        "tool": "cs_list_beacons",
        "request": {},
        "truncated_arguments": [],
        "next_step": "Correct the named arguments to match the tool's input schema before retrying.",
    }
