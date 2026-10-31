"""OSV affected-range evaluation using PEP 440 ordering."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from packaging.version import InvalidVersion, Version


def version_in_events(version: str, events: Iterable[Mapping[str, str | None]]) -> bool | None:
    """Return whether a version is in an OSV event interval, or None if unusable."""
    try:
        candidate = Version(version)
    except InvalidVersion:
        return None
    lower: Version | None = None
    upper: Version | None = None
    closed_interval_seen = False
    for event in events:
        if event.get("introduced") is not None:
            value = event["introduced"]
            if value not in {"", "*"}:
                try:
                    lower = Version(value)
                except InvalidVersion:
                    return None
            else:
                lower = None
        elif event.get("fixed") is not None or event.get("limit") is not None:
            value = event.get("fixed") or event.get("limit")
            try:
                upper = Version(value) if value else None
            except InvalidVersion:
                return None
            if lower is not None and lower <= candidate < upper:
                return True
            if lower is None and candidate < upper:
                return True
            closed_interval_seen = True
            lower, upper = None, None
        elif event.get("last_affected") is not None:
            try:
                upper = Version(event["last_affected"])
            except InvalidVersion:
                return None
            if lower is not None and lower <= candidate <= upper:
                return True
            if lower is None and candidate <= upper:
                return True
            closed_interval_seen = True
            lower, upper = None, None
    if lower is not None:
        return candidate >= lower
    return False if closed_interval_seen else None


def evaluate_ranges(version: str, ranges: Iterable[Mapping]) -> bool | None:
    usable = False
    for item in ranges:
        result = version_in_events(version, item.get("events", []))
        if result is True:
            return True
        usable = usable or result is not None
    return False if usable else None
