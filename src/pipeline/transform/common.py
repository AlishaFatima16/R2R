"""Small deterministic helpers used by canonical transforms."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import pandas as pd


def content_hash(row: Mapping[str, Any], columns: Sequence[str]) -> str:
    values = []
    for column in columns:
        value = row.get(column)
        if value is None or pd_is_missing(value):
            value = None
        if isinstance(value, datetime):
            value = value.isoformat()
        values.append(value)
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def pd_is_missing(value: Any) -> bool:
    """Return whether a scalar is a Pandas null without treating lists as null."""
    try:
        result = pd.isna(value)
    except (TypeError, ValueError):
        return False
    return bool(result) if isinstance(result, bool) else False
