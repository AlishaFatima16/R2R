"""Contract models for OSV advisories, and validation of saved query pages.

A saved OSV page holds many advisories. Each one is validated on its own, so one bad
advisory goes to quarantine and the others in the page still load.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from pipeline.validate.common import Contract, as_utc
from pipeline.validate.errors import quarantine_row, rows_from_error

OSV_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]*-.+$")
EVENT_TYPES = ("introduced", "fixed", "last_affected", "limit")


class OsvEvent(Contract):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self):
        given = [name for name in EVENT_TYPES if getattr(self, name) is not None]
        if len(given) != 1:
            raise ValueError(f"an event needs exactly one of {EVENT_TYPES}, got {given}")
        return self

    @property
    def event_type(self) -> str:
        return next(name for name in EVENT_TYPES if getattr(self, name) is not None)

    @property
    def version_string(self) -> str:
        return getattr(self, self.event_type)


class OsvRange(Contract):
    type: Literal["SEMVER", "ECOSYSTEM", "GIT"]
    events: list[OsvEvent]
    repo: str | None = None

    @model_validator(mode="after")
    def _checks(self):
        if not self.events:
            raise ValueError("a range needs at least one event")
        if self.type == "GIT" and not self.repo:
            raise ValueError("a GIT range needs a repo")
        return self


class OsvPackage(Contract):
    name: str
    ecosystem: str


class OsvAffected(Contract):
    package: OsvPackage | None = None
    ranges: list[OsvRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class OsvSeverity(Contract):
    type: str
    score: str
    source: str | None = None


class OsvVuln(Contract):
    id: str
    modified: datetime
    published: datetime | None = None
    withdrawn: datetime | None = None
    summary: str | None = None
    details: str | None = None
    schema_version: str | None = None
    aliases: list[str] = Field(default_factory=list)
    severity: list[OsvSeverity] = Field(default_factory=list)
    affected: list[OsvAffected] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value):
        if not OSV_ID.match(value):
            raise ValueError("id must look like <DATABASE>-<ENTRY>")
        return value

    @field_validator("modified", "published", "withdrawn")
    @classmethod
    def _utc(cls, value):
        return as_utc(value)

    @property
    def dates_out_of_order(self) -> bool:
        """Soft problem: the advisory says it was modified before it was published."""
        return self.published is not None and self.modified < self.published


@dataclass
class OsvPageResult:
    vulns: list[OsvVuln] = field(default_factory=list)
    quarantine: list[dict] = field(default_factory=list)


def validate_osv_page(body, raw_object_id=None) -> OsvPageResult:
    """Validate the body of one saved OSV query page. A page with no advisories is {}."""
    if not isinstance(body, dict):
        row = quarantine_row(
            raw_object_id, "type_error", "", f"expected a JSON object, got {type(body).__name__}"
        )
        return OsvPageResult([], [row])
    items = body.get("vulns", [])
    if not isinstance(items, list):
        row = quarantine_row(
            raw_object_id, "type_error", "vulns", f"expected a list, got {type(items).__name__}"
        )
        return OsvPageResult([], [row])

    result = OsvPageResult()
    for index, item in enumerate(items):
        context = item.get("id", "") if isinstance(item, dict) else ""
        try:
            result.vulns.append(OsvVuln.model_validate(item))
        except ValidationError as error:
            result.quarantine += rows_from_error(
                error, raw_object_id, prefix=f"vulns[{index}]", context=str(context)
            )
    return result
