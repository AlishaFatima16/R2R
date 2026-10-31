"""Small deterministic helpers used by canonical transforms."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any


def content_hash(row: Mapping[str, Any], columns: Sequence[str]) -> str:
    values = []
    for column in columns:
        value = row.get(column)
        if isinstance(value, datetime):
            value = value.isoformat()
        values.append(value)
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(__import__("datetime").UTC)
