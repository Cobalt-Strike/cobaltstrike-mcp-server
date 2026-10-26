"""Measure what a client receives for a result, and shorten its free text to a ceiling.

Listings are paged at record boundaries by ``listing_pages``; this module caps every other
result, and the lone row a page cannot split.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pydantic
import pydantic_core

from cs_server_mcp import agent_text

MAX_REPORTED_TRUNCATED_FIELDS = 20
# Never shortened: navigation, identifiers, and submitted arguments.
PROTECTED_KEYS = frozenset(
    {
        "next_offset",
        "_truncation",
        "command_arguments",
        "submitted_arguments",
        "artifact_reference",
        "url",
        "command_execution_id",
        "beacon_id",
        "download_id",
        "screenshot_id",
        "command_name",
        "parent_beacon_id",
        "job_id",
        "stop_command_execution_id",
        "name",
        "key",
    }
)
# Strings at or under the floor (hashes, enums, timestamps) are never shortened either.
FIELD_FLOOR = 256
_TRUNCATION_RESERVE = 1_500


def to_plain_data(value: Any) -> Any:
    if isinstance(value, pydantic.BaseModel):
        return value.model_dump(mode="json", by_alias=False)
    if isinstance(value, Mapping):
        return {str(key): to_plain_data(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [to_plain_data(item) for item in value]
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    return value


def serialized_size(value: Any) -> int:
    """Characters of the indented JSON the MCP SDK renders for ``value``."""
    return len(pydantic_core.to_json(value, fallback=str, indent=2).decode())


Measure = Callable[[Any], int]


def structured_size(output_model: Any) -> Measure:
    """Size of the validated dump the SDK sends as ``structuredContent``, nulls for omitted
    optional fields included."""
    adapter = pydantic.TypeAdapter(output_model)

    def measure(value: Any) -> int:
        validated = adapter.validate_python(value, by_alias=True, by_name=True)
        if isinstance(validated, pydantic.BaseModel):
            dump = validated.model_dump(mode="json", by_alias=True)
        else:
            dump = adapter.dump_python(validated, mode="json", by_alias=True)
        return serialized_size(dump)

    return measure


def _shortenable_lengths(value: Any) -> list[int]:
    lengths: list[int] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            if len(item) > FIELD_FLOOR:
                lengths.append(len(item))
        elif isinstance(item, Mapping):
            for key, child in item.items():
                if str(key) not in PROTECTED_KEYS:
                    visit(child)
        elif isinstance(item, Sequence) and not isinstance(item, bytes | bytearray):
            for child in item:
                visit(child)

    visit(value)
    return lengths


def _field_cap(lengths: Sequence[int], excess: int) -> int | None:
    """The largest per-string cap, at or above the floor, that removes ``excess`` characters."""

    def removed(cap: int) -> int:
        return sum(length - cap for length in lengths if length > cap)

    if removed(FIELD_FLOOR) < excess:
        return None
    low, high = FIELD_FLOOR, max(lengths, default=FIELD_FLOOR)
    while low < high:
        middle = (low + high + 1) // 2
        if removed(middle) >= excess:
            low = middle
        else:
            high = middle - 1
    return low


@dataclass
class _ShortenTally:
    omitted_chars: int = 0
    count: int = 0
    fields: list[str] = field(default_factory=list)


def _shorten_strings(value: Any, cap: int, tally: _ShortenTally) -> Any:
    def visit(item: Any, path: str) -> Any:
        if isinstance(item, str):
            if len(item) <= cap:
                return item
            tally.omitted_chars += len(item) - cap
            tally.count += 1
            if len(tally.fields) < MAX_REPORTED_TRUNCATED_FIELDS:
                tally.fields.append(path)
            return item[:cap]
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, child in item.items():
                key_string = str(key)
                if key_string in PROTECTED_KEYS:
                    result[key_string] = child
                else:
                    result[key_string] = visit(
                        child, f"{path}.{key_string}" if path else key_string
                    )
            return result
        if isinstance(item, Sequence) and not isinstance(item, bytes | bytearray):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(item)]
        return item

    return visit(value, "")


def shorten_free_text(
    value: Mapping[str, Any], *, target: int, measure: Measure
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bring ``value`` within ``target`` by shortening free text, and report what was cut.

    One shared cap applies to every string over ``FIELD_FLOOR``, so the longest give way
    first. The cap is chosen on raw lengths, which never undershoots: cutting a string
    removes at least as many rendered characters as raw ones. When the floor itself is not
    enough the result stays over ``target`` and the caller sees that.
    """
    excess = measure(value) - target
    if excess <= 0:
        return dict(value), {}
    lengths = _shortenable_lengths(value)
    if not lengths:
        return dict(value), {}
    cap = _field_cap(lengths, excess)
    if cap is None:
        cap = FIELD_FLOOR
    tally = _ShortenTally()
    shortened = _shorten_strings(value, cap, tally)
    if not tally.count:
        return dict(value), {}
    report = {
        "field_char_limit": cap,
        "omitted_chars": tally.omitted_chars,
        "fields": tally.fields,
    }
    if tally.count > len(tally.fields):
        report["unreported_fields"] = tally.count - len(tally.fields)
    return shortened, report


def fit_truncation_report(bounded: dict[str, Any], *, max_chars: int, measure: Measure) -> bool:
    """Shed reported field paths from ``_truncation`` until the result fits; returns whether it
    does. The paths are kept when the result is over the ceiling even without them."""
    truncation = bounded["_truncation"]
    fields = truncation.get("fields")
    if measure(bounded) <= max_chars:
        return True
    if not fields:
        return False
    unreported = truncation.get("unreported_fields", 0)
    bare = {**bounded, "_truncation": {**truncation, "fields": [], "unreported_fields": 1}}
    if measure(bare) > max_chars:
        return False
    while measure(bounded) > max_chars and fields:
        fields.pop()
        unreported += 1
        truncation["unreported_fields"] = unreported
    return True


def bound_response(value: Any, *, max_chars: int, measure: Measure = serialized_size) -> Any:
    """Cap a non-listing result at ``max_chars``: only free text gives way, no row is dropped,
    and a result still over the ceiling at the floor is sent whole and flagged
    ``exceeds_ceiling``. Non-objects pass through."""
    if not isinstance(value, Mapping):
        return value
    original = measure(value)
    if original <= max_chars:
        return value
    shortened, report = shorten_free_text(
        value, target=max_chars - _TRUNCATION_RESERVE, measure=measure
    )
    truncation: dict[str, Any] = {
        "truncated": True,
        "reason": "max_response_chars",
        "max_response_chars": max_chars,
        "response_chars": original,
        **report,
        "next_step": (
            agent_text.RESULT_SHORTENED_NEXT_STEP if report else agent_text.RESULT_EXCEEDS_NEXT_STEP
        ),
    }
    existing = value.get("_truncation")
    if isinstance(existing, Mapping):
        truncation = {**existing, **truncation}
    bounded = {**shortened, "_truncation": truncation}
    if not fit_truncation_report(bounded, max_chars=max_chars, measure=measure):
        truncation["exceeds_ceiling"] = True
        truncation["next_step"] = agent_text.RESULT_EXCEEDS_NEXT_STEP
    return bounded
