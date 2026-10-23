"""Every public coroutine on ``CobaltStrikeClient`` must exist on ``FakeTeamServer`` with the
same parameters."""

from __future__ import annotations

import inspect

from cs_server_mcp.client import CobaltStrikeClient
from tests.fake_teamserver import FakeTeamServer


def _public_operations(cls: type) -> dict[str, list[tuple[str, inspect._ParameterKind, object]]]:
    operations = {}
    for name, member in inspect.getmembers(cls, inspect.iscoroutinefunction):
        if name.startswith("_"):
            continue
        parameters = list(inspect.signature(member).parameters.values())[1:]
        operations[name] = [(p.name, p.kind, p.default) for p in parameters]
    return operations


def test_fake_teamserver_offers_every_client_operation_with_the_same_parameters() -> None:
    real = _public_operations(CobaltStrikeClient)
    fake = _public_operations(FakeTeamServer)

    assert set(real) <= set(fake), (
        f"fake is missing client operations: {sorted(set(real) - set(fake))}"
    )
    assert {name: fake[name] for name in real} == real
