"""Shared pieces for the contract models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


class Contract(BaseModel):
    """Contract models mirror a source's response and ignore fields we do not use."""

    model_config = ConfigDict(extra="ignore")


def as_utc(value: datetime | None) -> datetime | None:
    """Aware timestamps become UTC. Naive ones are taken to be UTC (the source gave no zone)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
