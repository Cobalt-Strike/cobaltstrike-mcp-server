"""Bound list responses at a record boundary and continue with a numeric offset."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from cs_server_mcp import agent_text
from cs_server_mcp.serialization import Measure, fit_truncation_report, shorten_free_text

ROWS_KEY = "results"
_TRUNCATION_RESERVE = 1_500


def rows_key(value: Any) -> str | None:
    if isinstance(value, Mapping) and isinstance(value.get(ROWS_KEY), list):
        return ROWS_KEY
    return None


def _with_rows(page: Mapping[str, Any], key: str, rows: Sequence[Any]) -> dict[str, Any]:
    """Rows go last so a client-side cut keeps the paging keys."""
    return {**{name: value for name, value in page.items() if name != key}, key: list(rows)}


class ListingRequest:
    def __init__(self, *, arguments: Mapping[str, Any]) -> None:
        self._offset = arguments.get("offset") or 0

    def bound(self, page: Mapping[str, Any], *, max_chars: int, measure: Measure) -> dict[str, Any]:
        """Keep whole rows under ``max_chars`` and advance ``next_offset``."""
        key = rows_key(page)
        if key is None:
            raise ValueError("bound() takes a listing")
        rows = page[key]
        has_more = bool(page.get("has_more"))
        envelope = {name: value for name, value in page.items() if name not in {key, "next_cursor"}}
        envelope["next_offset"] = (
            page.get("next_offset", self._offset + len(rows)) if has_more else None
        )
        whole = _with_rows(envelope, key, rows)
        original = measure(whole)
        if original <= max_chars:
            return whole

        def continued(kept: int) -> dict[str, Any]:
            return _with_rows(
                {
                    **envelope,
                    "has_more": True,
                    "next_offset": self._offset + kept,
                    "_truncation": self._report(max_chars, original, omitted=len(rows) - kept),
                },
                key,
                rows[:kept],
            )

        kept = _largest_fitting(len(rows) - 1, lambda count: measure(continued(count)) <= max_chars)
        if kept:
            return continued(kept)
        return self._lone_row(
            continued(1) if len(rows) > 1 else whole,
            key,
            max_chars=max_chars,
            measure=measure,
            original=original,
            remaining=len(rows) - 1,
        )

    def _lone_row(
        self,
        page: Mapping[str, Any],
        key: str,
        *,
        max_chars: int,
        measure: Measure,
        original: int,
        remaining: int,
    ) -> dict[str, Any]:
        """A single row over the ceiling on its own: its free text is cut and the report says so."""
        shortened, report = shorten_free_text(
            page, target=max_chars - _TRUNCATION_RESERVE, measure=measure
        )
        explanation = (
            agent_text.LISTING_LONE_ROW_SHORTENED if report else agent_text.LISTING_LONE_ROW_WHOLE
        )
        truncation = {
            **self._report(max_chars, original, omitted=remaining),
            **report,
            "next_step": (
                explanation
                if remaining == 0
                else f"{explanation} {agent_text.LISTING_SPLIT_NEXT_STEP}"
            ),
        }
        bounded = _with_rows({**shortened, "_truncation": truncation}, key, shortened[key])
        if not fit_truncation_report(bounded, max_chars=max_chars, measure=measure):
            truncation["exceeds_ceiling"] = True
        return bounded

    def _report(self, max_chars: int, response_chars: int, *, omitted: int) -> dict[str, Any]:
        return {
            "truncated": True,
            "reason": "max_response_chars",
            "max_response_chars": max_chars,
            "response_chars": response_chars,
            **({"omitted_items": omitted} if omitted else {}),
            "next_step": agent_text.LISTING_SPLIT_NEXT_STEP,
        }


def _largest_fitting(high: int, fits: Callable[[int], bool]) -> int:
    best, low = 0, 1
    while low <= high:
        middle = (low + high) // 2
        if fits(middle):
            best, low = middle, middle + 1
        else:
            high = middle - 1
    return best
