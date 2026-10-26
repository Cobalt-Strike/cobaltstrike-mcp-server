"""A virtual clock for the event loop, so waits in the code under test take no wall time.

The ``clock`` fixture points ``command_lifecycle.utc_now`` and ``monotonic`` at the same
virtual time, so every deadline comparison stays exact.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

VIRTUAL_START = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


class VirtualTimeLoop(asyncio.SelectorEventLoop):
    """Jumps ``time()`` to the earliest live timer whenever no callback is ready. Relies on
    nothing awaited doing selector I/O (tests that do are marked ``wall_clock``)."""

    def __init__(self) -> None:
        super().__init__()
        self._virtual_time = 0.0

    def time(self) -> float:
        return self._virtual_time

    def _run_once(self) -> None:
        if not self._ready and not self._stopping:
            due = [handle._when for handle in self._scheduled if not handle._cancelled]
            if due:
                self._virtual_time = max(self._virtual_time, min(due))
        super()._run_once()


@dataclass(frozen=True)
class VirtualClock:
    loop: asyncio.AbstractEventLoop

    def now(self) -> datetime:
        return VIRTUAL_START + timedelta(seconds=self.loop.time())

    def after(self, seconds: float) -> datetime:
        return self.now() + timedelta(seconds=seconds)

    def elapsed(self) -> float:
        return self.loop.time()

    @staticmethod
    def epoch_ms(moment: datetime) -> int:
        return int(moment.timestamp() * 1000)
