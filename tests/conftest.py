from __future__ import annotations

import asyncio

import pytest

from cs_server_mcp import command_lifecycle
from tests.fake_teamserver import FakeTeamServer
from tests.virtual_time import VirtualClock, VirtualTimeLoop


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "wall_clock: run on a real event loop instead of the virtual-time loop"
    )


def pytest_asyncio_loop_factories(config: pytest.Config, item: pytest.Item) -> dict[str, type]:
    if item.get_closest_marker("wall_clock") is not None:
        return {"wall-clock": asyncio.new_event_loop}
    return {"virtual-time": VirtualTimeLoop}


@pytest.fixture
async def clock(monkeypatch: pytest.MonkeyPatch) -> VirtualClock:
    loop = asyncio.get_running_loop()
    assert isinstance(loop, VirtualTimeLoop), "tests run on the virtual-time loop"
    clock = VirtualClock(loop)
    monkeypatch.setattr(command_lifecycle, "utc_now", clock.now)
    monkeypatch.setattr(command_lifecycle, "monotonic", loop.time)
    return clock


@pytest.fixture
def teamserver(clock: VirtualClock) -> FakeTeamServer:
    return FakeTeamServer(clock)
