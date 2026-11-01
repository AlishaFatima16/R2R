"""Contract models for the PyPI JSON API, and validation of saved responses.

Two endpoints are used:
    /pypi/<name>/json            the project: info about the latest release, plus a map of
                                 every release to its files (model PypiProject)
    /pypi/<name>/<version>/json  one release, including its own requires_dist (PypiVersion)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from pydantic import Field, ValidationError, field_validator

from pipeline.validate.common import Contract, as_utc
from pipeline.validate.errors import quarantine_row, rows_from_error


class PypiFile(Contract):
    upload_time_iso_8601: datetime | None = None
    yanked: bool = False
    yanked_reason: str | None = None
    requires_python: str | None = None

    @field_validator("upload_time_iso_8601")
    @classmethod
    def _utc(cls, value):
        return as_utc(value)


class PypiInfo(Contract):
    name: str
    version: str
    summary: str | None = None
    home_page: str | None = None
    project_urls: dict[str, str] | None = None
    license: str | None = None
    requires_python: str | None = None
    requires_dist: list[str] | None = None
    yanked: bool = False
    yanked_reason: str | None = None

    @field_validator("name", "version")
    @classmethod
    def _not_empty(cls, value):
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class PypiVulnerability(Contract):
    id: str
    aliases: list[str] = Field(default_factory=list)
    fixed_in: list[str] = Field(default_factory=list)
    source: str | None = None
    withdrawn: datetime | None = None


class PypiProject(Contract):
    info: PypiInfo
    last_serial: int | None = None
    releases: dict[str, list[PypiFile]] = Field(default_factory=dict)
    vulnerabilities: list[PypiVulnerability] = Field(default_factory=list)


class PypiVersion(Contract):
    info: PypiInfo
    last_serial: int | None = None
    urls: list[PypiFile] = Field(default_factory=list)
    vulnerabilities: list[PypiVulnerability] = Field(default_factory=list)


@dataclass
class PypiResult:
    value: PypiProject | PypiVersion | None = None
    quarantine: list[dict] = field(default_factory=list)


def _validate(model, body, raw_object_id) -> PypiResult:
    if not isinstance(body, dict):
        row = quarantine_row(
            raw_object_id, "type_error", "", f"expected a JSON object, got {type(body).__name__}"
        )
        return PypiResult(None, [row])
    try:
        return PypiResult(model.model_validate(body))
    except ValidationError as error:
        return PypiResult(None, rows_from_error(error, raw_object_id))


def validate_pypi_project(body, raw_object_id=None) -> PypiResult:
    """Validate the body of a saved /pypi/<name>/json response (skip 404 lines first)."""
    return _validate(PypiProject, body, raw_object_id)


def validate_pypi_version(body, raw_object_id=None) -> PypiResult:
    """Validate the body of a saved /pypi/<name>/<version>/json response."""
    return _validate(PypiVersion, body, raw_object_id)
