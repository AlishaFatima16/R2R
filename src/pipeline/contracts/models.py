"""Pydantic contracts for the PyPI and OSV response shapes.

The API payloads are intentionally modelled at the boundary.  Unknown fields
are retained by the raw layer but ignored here so API additions do not break a
run.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class PyPIFile(ContractModel):
    filename: str
    upload_time: datetime | None = None
    yanked: bool = False
    yanked_reason: str | None = None


class PyPIInfo(ContractModel):
    name: str
    version: str
    summary: str | None = None
    home_page: str | None = None
    project_url: str | None = None
    project_urls: dict[str, str] | None = None
    license: str | None = None
    requires_python: str | None = None
    requires_dist: list[str] | None = None


class PyPIProjectResponse(ContractModel):
    info: PyPIInfo
    releases: dict[str, list[PyPIFile]] = Field(default_factory=dict)
    last_serial: int | None = None


class PyPIReleaseResponse(ContractModel):
    info: PyPIInfo
    urls: list[PyPIFile] = Field(default_factory=list)
    last_serial: int | None = None


class OSVEvent(ContractModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @field_validator("introduced", "fixed", "last_affected", "limit")
    @classmethod
    def non_empty_event(cls, value: str | None) -> str | None:
        return value if value is None or value.strip() else None


class OSVRange(ContractModel):
    type: str
    repo: str | None = None
    events: list[OSVEvent] = Field(default_factory=list)


class OSVAffectedPackage(ContractModel):
    package: str = Field(alias="name")
    ecosystem: str | None = None
    purl: str | None = None


class OSVAffected(ContractModel):
    package: OSVAffectedPackage
    ranges: list[OSVRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class OSVSeverity(ContractModel):
    type: str
    score: str
    source: str | None = None


class OSVResponse(ContractModel):
    id: str
    published: datetime | None = None
    modified: datetime
    withdrawn: datetime | None = None
    summary: str | None = None
    details: str | None = None
    schema_version: str | None = Field(default=None, alias="schema_version")
    aliases: list[str] = Field(default_factory=list)
    severity: list[OSVSeverity] = Field(default_factory=list)
    affected: list[OSVAffected] = Field(default_factory=list)


def validate_payload(model: type[ContractModel], payload: Any) -> ContractModel:
    """Validate one decoded API payload and let Pydantic's error surface intact."""
    return model.model_validate(payload)
