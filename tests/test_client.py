"""The HTTP client against a local aiohttp server over real sockets, which is why these run
on the wall clock. What ``FakeTeamServer`` assumes about the client is pinned here."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cs_sdk_python.api_client.exceptions import ApiException

from cs_server_mcp import client as client_module
from cs_server_mcp.client import CobaltStrikeClient
from cs_server_mcp.config import Settings

pytestmark = pytest.mark.wall_clock

LOGIN = ("POST", "/api/auth/login")
BEACONS = ("GET", "/api/v1/beacons")
CREDENTIALS = ("GET", "/api/v1/data/credentials")
ADD_CREDENTIAL = ("POST", "/api/v1/data/credentials")
PASSWORD = "hunter2"


@dataclass
class Reply:
    status: int = 200
    body: bytes = b""


@dataclass
class Received:
    method: str
    path: str
    authorization: str | None
    body: Any


@dataclass
class HttpTeamServer:
    """Replies for a route are served in order; the last one repeats."""

    url: str = ""
    received: list[Received] = field(default_factory=list)
    _replies: dict[tuple[str, str], list[Reply]] = field(default_factory=dict)

    def reply(self, route: tuple[str, str], *, status: int = 200, json_body: Any = None) -> None:
        body = b"" if json_body is None else json.dumps(json_body).encode()
        self._replies.setdefault(route, []).append(Reply(status=status, body=body))

    def logs_in_with(self, token: str, *, expires_in: int | None = None) -> None:
        payload: dict[str, Any] = {"access_token": token}
        if expires_in is not None:
            payload["expires_in"] = expires_in
        self.reply(LOGIN, json_body=payload)

    def received_for(self, route: tuple[str, str]) -> list[Received]:
        return [r for r in self.received if (r.method, r.path) == route]

    async def handle(self, request: web.Request) -> web.Response:
        raw = await request.read()
        self.received.append(
            Received(
                request.method,
                request.path,
                request.headers.get("Authorization"),
                json.loads(raw) if raw else None,
            )
        )
        queue = self._replies.get((request.method, request.path), [Reply(status=404)])
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        return web.Response(status=reply.status, body=reply.body, content_type="application/json")


@pytest.fixture
async def http_teamserver() -> AsyncIterator[HttpTeamServer]:
    teamserver = HttpTeamServer()
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", teamserver.handle)
    async with TestServer(app) as server:
        teamserver.url = f"http://127.0.0.1:{server.port}"
        yield teamserver


def settings_for(teamserver: HttpTeamServer) -> Settings:
    return Settings(url=teamserver.url, username="mcp-service", password=PASSWORD)


class Ticking:
    def __init__(self) -> None:
        self.seconds = 0.0

    def __call__(self) -> float:
        return self.seconds


async def test_list_beacons_logs_in_first_and_sends_the_token_as_a_bearer(
    http_teamserver: HttpTeamServer,
) -> None:
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.reply(BEACONS, json_body=[{"bid": "1234", "computer": "WS01"}])

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        rows = await client.list_beacons()

    assert rows == [{"bid": "1234", "computer": "WS01"}]
    login, beacons = http_teamserver.received
    assert (login.method, login.path) == LOGIN
    assert login.authorization is None
    assert login.body == {
        "username": "mcp-service",
        "password": "hunter2",
        "duration_ms": 86_400_000,
    }
    assert (beacons.method, beacons.path, beacons.authorization) == (*BEACONS, "Bearer tok-1")


@pytest.mark.parametrize("credential_id", [None, "credential-1"])
async def test_credential_reads_keep_read_only_fields_and_exact_values(
    http_teamserver: HttpTeamServer, credential_id: str | None
) -> None:
    record = {
        "id": "credential-1",
        "user": "alice",
        "secret": "  test secret\n",
        "created": "2026-11-16T12:00:00Z",
        "realm": "EXAMPLE",
        "secret_type": "plaintext",
        "host": "WS01",
        "source": "operator",
        "note": "test account",
    }
    route = CREDENTIALS if credential_id is None else ("GET", f"{CREDENTIALS[1]}/{credential_id}")
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.reply(route, json_body=[record] if credential_id is None else record)

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        result = (
            await client.list_credentials()
            if credential_id is None
            else await client.get_credential(credential_id)
        )

    assert result == ([record] if credential_id is None else record)
    assert http_teamserver.received_for(route)[0].authorization == "Bearer tok-1"


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
async def test_add_credential_sends_the_sdk_wire_fields_and_accepts_an_empty_response(
    http_teamserver: HttpTeamServer, metadata: dict[str, str]
) -> None:
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.reply(ADD_CREDENTIAL)

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        result = await client.add_credential(username="alice", secret="  test secret\n", **metadata)

    assert result is None
    [request] = http_teamserver.received_for(ADD_CREDENTIAL)
    assert request.authorization == "Bearer tok-1"
    assert request.body == {"user": "alice", "secret": "  test secret\n", **metadata}


async def test_failed_credential_post_is_not_retried(http_teamserver: HttpTeamServer) -> None:
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.reply(ADD_CREDENTIAL, status=500)

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        with pytest.raises(ApiException) as raised:
            await client.add_credential(username="alice", secret="test")

    assert raised.value.status == 500
    assert len(http_teamserver.received_for(ADD_CREDENTIAL)) == 1


async def test_request_rejected_with_401_logs_in_again_and_retries_once(
    http_teamserver: HttpTeamServer,
) -> None:
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.logs_in_with("tok-2")
    http_teamserver.reply(BEACONS, status=401)
    http_teamserver.reply(BEACONS, json_body=[])

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        rows = await client.list_beacons()

    assert rows == []
    assert [r.authorization for r in http_teamserver.received_for(BEACONS)] == [
        "Bearer tok-1",
        "Bearer tok-2",
    ]


async def test_token_is_refreshed_before_the_server_would_expire_it(
    http_teamserver: HttpTeamServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 100 s token refreshes halfway, since half its lifetime is under the minute margin.
    http_teamserver.logs_in_with("tok-1", expires_in=100)
    http_teamserver.logs_in_with("tok-2", expires_in=100)
    http_teamserver.reply(BEACONS, json_body=[])
    clock = Ticking()
    monkeypatch.setattr(client_module, "monotonic", clock)

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        await client.list_beacons()
        clock.seconds = 49.0
        await client.list_beacons()
        clock.seconds = 50.0
        await client.list_beacons()

    assert [r.authorization for r in http_teamserver.received_for(BEACONS)] == [
        "Bearer tok-1",
        "Bearer tok-1",
        "Bearer tok-2",
    ]


async def test_http_failure_with_an_empty_body_carries_an_empty_body(
    http_teamserver: HttpTeamServer,
) -> None:
    # What FakeTeamServer's api_error(404) assumes.
    http_teamserver.logs_in_with("tok-1")
    http_teamserver.reply(BEACONS, status=404)

    async with CobaltStrikeClient(settings_for(http_teamserver), password=PASSWORD) as client:
        with pytest.raises(ApiException) as raised:
            await client.list_beacons()

    assert raised.value.status == 404
    assert raised.value.body == ""
