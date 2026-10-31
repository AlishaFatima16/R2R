"""PyPI response validation and canonical Pandas transformations."""

from __future__ import annotations

from collections.abc import Mapping

import pandas as pd
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from pipeline.contracts.models import PyPIProjectResponse
from pipeline.contracts.records import QuarantineRecord, quarantine_from_error
from pipeline.transform.common import content_hash, utc_datetime


def _repo_url(info) -> str | None:
    urls = info.project_urls or {}
    return info.home_page or info.project_url or next(iter(urls.values()), None)


def transform_pypi_project(
    payload: Mapping, *, raw_object_id: int | None = None, in_seed: bool = True,
    seed_tier: str | None = "A",
) -> tuple[dict[str, pd.DataFrame], list[QuarantineRecord]]:
    """Transform one PyPI project JSON response into package, release and dependency frames."""
    try:
        project = PyPIProjectResponse.model_validate(payload)
    except (ValidationError, TypeError, ValueError) as error:
        return {}, [quarantine_from_error(error, raw_object_id=raw_object_id)]

    canonical_name = canonicalize_name(project.info.name)
    package = {
        "canonical_name": canonical_name,
        "display_name": project.info.name,
        "in_seed": in_seed,
        "seed_tier": seed_tier if in_seed else None,
        "summary": project.info.summary,
        "repo_url": _repo_url(project.info),
        "license_raw": project.info.license,
        "latest_version": project.info.version,
        "last_serial": project.last_serial,
        "raw_object_id": raw_object_id,
    }
    package["content_hash"] = content_hash(package, tuple(k for k in package if k != "content_hash"))
    releases: list[dict] = []
    dependencies: list[dict] = []
    for version_text, files in project.releases.items():
        try:
            parsed = Version(version_text)
            valid, rank, is_pre, is_dev = True, 0, parsed.is_prerelease, parsed.is_devrelease
        except InvalidVersion:
            valid, rank, is_pre, is_dev = False, None, False, False
        uploads = [utc_datetime(file.upload_time) for file in files if file.upload_time is not None]
        yanked_file = next((file for file in files if file.yanked), None)
        release = {
            "canonical_name": canonical_name,
            "version": version_text,
            "version_valid": valid,
            "version_rank": rank,
            "is_prerelease": is_pre,
            "is_dev": is_dev,
            "uploaded_at": min(uploads) if uploads else None,
            "yanked": yanked_file is not None,
            "yanked_reason": yanked_file.yanked_reason if yanked_file else None,
            "requires_python": project.info.requires_python,
            "deps_fetched": True,
            "raw_object_id": raw_object_id,
        }
        for raw_requirement in project.info.requires_dist or []:
            try:
                requirement = Requirement(raw_requirement)
                dependency = {
                    "canonical_name": canonical_name,
                    "version": version_text,
                    "raw_requirement": raw_requirement,
                    "requirement_valid": True,
                    "target_canonical_name": canonicalize_name(requirement.name),
                    "extras": sorted(requirement.extras) or None,
                    "specifier": str(requirement.specifier) or None,
                    "marker": str(requirement.marker) if requirement.marker else None,
                    "is_extra_only": "extra" in str(requirement.marker) if requirement.marker else False,
                    "is_conditional": requirement.marker is not None,
                }
            except InvalidRequirement:
                dependency = {
                    "canonical_name": canonical_name,
                    "version": version_text,
                    "raw_requirement": raw_requirement,
                    "requirement_valid": False,
                    "target_canonical_name": None,
                    "extras": None,
                    "specifier": None,
                    "marker": None,
                    "is_extra_only": False,
                    "is_conditional": False,
                }
            dependency["content_hash"] = content_hash(
                dependency, tuple(k for k in dependency if k != "content_hash")
            )
            dependencies.append(dependency)
        releases.append(release)
    release_frame = rank_releases(pd.DataFrame(releases))
    for row in release_frame.to_dict("records"):
        row["content_hash"] = content_hash(
            row, tuple(k for k in row if k != "content_hash")
        )
    release_frame = pd.DataFrame(release_frame.to_dict("records"))
    return (
        {
            "package": pd.DataFrame([package]),
            "release": release_frame,
            "dependency": pd.DataFrame(dependencies),
        },
        [],
    )


def rank_releases(frame: pd.DataFrame) -> pd.DataFrame:
    """Assign stable per-package ranks to valid releases; invalid versions stay null."""
    result = frame.copy()
    valid = result["version_valid"]
    result.loc[valid, "version_rank"] = (
        result.loc[valid].assign(_parsed=result.loc[valid, "version"].map(Version))
        .sort_values(["canonical_name", "_parsed"])
        .groupby("canonical_name")
        .cumcount()
        .add(1)
    )
    result["version_rank"] = result["version_rank"].astype("Int64")
    return result
