"""Transform validated PyPI project and per-release responses into canonical frames."""

from __future__ import annotations

import re
from collections.abc import Iterable

import pandas as pd
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pipeline.transform.common import content_hash
from pipeline.validate.pypi import PypiProject, PypiVersion, validate_pypi_project

PACKAGE_COLUMNS = (
    "canonical_name", "display_name", "in_seed", "seed_tier", "summary", "repo_url",
    "license_raw", "latest_version", "last_serial", "raw_object_id", "content_hash",
)
RELEASE_COLUMNS = (
    "canonical_name", "version", "version_valid", "version_rank", "is_prerelease",
    "is_dev", "uploaded_at", "yanked", "yanked_reason", "requires_python",
    "deps_fetched", "raw_object_id", "content_hash",
)
DEPENDENCY_COLUMNS = (
    "canonical_name", "version", "raw_requirement", "requirement_valid", "target_name",
    "extras", "specifier", "marker", "is_extra_only", "is_conditional",
)


def _repo_url(project: PypiProject) -> str | None:
    urls = project.info.project_urls or {}
    return project.info.home_page or next(iter(urls.values()), None)


def _version_row(
    canonical_name: str,
    version: str,
    files: Iterable,
    release: PypiVersion | None,
    raw_object_id: int | None,
) -> dict:
    try:
        parsed = Version(version)
        valid, is_pre, is_dev = True, parsed.is_prerelease, parsed.is_devrelease
    except InvalidVersion:
        valid, is_pre, is_dev = False, False, False
    files = list(files)
    uploads = [file.upload_time_iso_8601 for file in files if file.upload_time_iso_8601]
    yanked_file = next((file for file in files if file.yanked), None)
    info = release.info if release else None
    requires_python = (
        info.requires_python if info and info.requires_python is not None
        else next((file.requires_python for file in files if file.requires_python), None)
    )
    return {
        "canonical_name": canonical_name,
        "version": version,
        "version_valid": valid,
        "version_rank": None,
        "is_prerelease": is_pre,
        "is_dev": is_dev,
        "uploaded_at": min(uploads) if uploads else None,
        "yanked": yanked_file is not None,
        "yanked_reason": yanked_file.yanked_reason if yanked_file else None,
        "requires_python": requires_python,
        "deps_fetched": release is not None,
        "raw_object_id": raw_object_id,
    }


def _dependency_rows(canonical_name: str, version: str, requirements: Iterable[str]) -> list[dict]:
    rows = []
    for raw_requirement in dict.fromkeys(requirements):
        try:
            requirement = Requirement(raw_requirement)
            marker = str(requirement.marker) if requirement.marker else None
            rows.append({
                "canonical_name": canonical_name,
                "version": version,
                "raw_requirement": raw_requirement,
                "requirement_valid": True,
                "target_name": canonicalize_name(requirement.name),
                "extras": sorted(requirement.extras) or None,
                "specifier": str(requirement.specifier) or None,
                "marker": marker,
                "is_extra_only": _is_extra_only(marker),
                "is_conditional": requirement.marker is not None,
            })
        except InvalidRequirement:
            rows.append({
                "canonical_name": canonical_name,
                "version": version,
                "raw_requirement": raw_requirement,
                "requirement_valid": False,
                "target_name": None,
                "extras": None,
                "specifier": None,
                "marker": None,
                "is_extra_only": False,
                "is_conditional": False,
            })
    return rows


def _is_extra_only(marker: str | None) -> bool:
    """Identify markers that constrain only the optional dependency extra."""
    if marker is None:
        return False
    names = set(
        re.findall(
            r"\b[A-Za-z_][A-Za-z0-9_]*\b(?=\s*(?:==|!=|>=|<=|>|<|in\b|not\s+in\b))",
            marker,
        )
    )
    return names == {"extra"}


def _finalize(frame: pd.DataFrame, columns: tuple[str, ...]) -> pd.DataFrame:
    return frame.reindex(columns=columns)


def transform_project(
    project: PypiProject,
    versions: dict[str, tuple[PypiVersion, int | None]],
    *,
    seed_tier: str,
    project_raw_object_id: int | None,
) -> dict[str, pd.DataFrame]:
    """Transform one validated project plus the per-release responses read for it."""
    canonical_name = canonicalize_name(project.info.name)
    package = {
        "canonical_name": canonical_name,
        "display_name": project.info.name,
        "in_seed": True,
        "seed_tier": seed_tier,
        "summary": project.info.summary,
        "repo_url": _repo_url(project),
        "license_raw": project.info.license,
        "latest_version": project.info.version,
        "last_serial": project.last_serial,
        "raw_object_id": project_raw_object_id,
    }
    package["content_hash"] = content_hash(package, PACKAGE_COLUMNS[:-1])
    release_rows = [
        _version_row(canonical_name, version, files, *versions.get(version, (None, None)))
        for version, files in project.releases.items()
    ]
    release_frame = pd.DataFrame(release_rows, columns=RELEASE_COLUMNS[:-1])
    release_frame = rank_releases(release_frame)
    release_frame["content_hash"] = [
        content_hash(row, RELEASE_COLUMNS[:-1])
        for row in release_frame.to_dict("records")
    ]
    dependency_rows = []
    for version, (release, _) in versions.items():
        dependency_rows.extend(
            _dependency_rows(canonical_name, version, release.info.requires_dist or [])
        )
    dependency_frame = _finalize(pd.DataFrame(dependency_rows), DEPENDENCY_COLUMNS)
    return {
        "package": _finalize(pd.DataFrame([package]), PACKAGE_COLUMNS),
        "release": _finalize(release_frame, RELEASE_COLUMNS),
        "dependency": dependency_frame,
    }


def rank_releases(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    if result.empty:
        return result
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


def transform_pypi_project(
    payload: dict, *, seed_tier: str, raw_object_id: int | None = None,
) -> tuple[dict[str, pd.DataFrame], list[dict]]:
    """Compatibility helper that validates one project before transforming it."""
    result = validate_pypi_project(payload, raw_object_id)
    if result.value is None:
        return {}, result.quarantine
    frames = transform_project(
        result.value, {}, seed_tier=seed_tier, project_raw_object_id=raw_object_id
    )
    return frames, []
