
"""Transform validated OSV advisories into canonical vulnerability frames."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pipeline.transform.common import content_hash
from pipeline.validate.osv import OsvVuln

VULNERABILITY_COLUMNS = (
    "vulnerability_id", "published_at", "modified_at", "withdrawn_at",
    "summary", "details", "schema_version", "dates_out_of_order",
    "raw_object_id", "content_hash",
)
ALIAS_COLUMNS = ("vulnerability_id", "alias")
SEVERITY_COLUMNS = ("vulnerability_id", "severity_type", "vector", "origin")

AFFECTED_PACKAGE_COLUMNS = (
    "vulnerability_id", "package_name", "entry_index",
)
AFFECTED_RANGE_COLUMNS = (
    "vulnerability_id", "entry_index", "range_index", "range_type", "repo",
)
AFFECTED_EVENT_COLUMNS = (
    "vulnerability_id", "entry_index", "range_index",
    "event_order", "event_type", "version_string",
)
AFFECTED_VERSION_COLUMNS = (
    "vulnerability_id", "entry_index", "version",
)
AFFECTED_RELEASE_COLUMNS = (
    "canonical_name", "version", "vulnerability_id", "entry_index",
    "in_range", "in_enumerated",
)


def _empty_frames() -> dict[str, pd.DataFrame]:
    return {
        "vulnerability": pd.DataFrame(columns=VULNERABILITY_COLUMNS),
        "vulnerability_alias": pd.DataFrame(columns=ALIAS_COLUMNS),
        "vulnerability_severity": pd.DataFrame(columns=SEVERITY_COLUMNS),
        "affected_package": pd.DataFrame(columns=AFFECTED_PACKAGE_COLUMNS),
        "affected_range": pd.DataFrame(columns=AFFECTED_RANGE_COLUMNS),
        "affected_event": pd.DataFrame(columns=AFFECTED_EVENT_COLUMNS),
        "affected_version": pd.DataFrame(columns=AFFECTED_VERSION_COLUMNS),
        "affected_release": pd.DataFrame(columns=AFFECTED_RELEASE_COLUMNS),
    }


def _in_pypi_range(version_string: str, events) -> bool | None:
    """Evaluate a PyPI version against OSV ecosystem-range events."""
    try:
        version = Version(version_string)
        introduced = None

        for event in events:
            event_type = event.event_type
            boundary = Version(event.version_string)

            if event_type == "introduced":
                introduced = boundary
            elif event_type == "fixed":
                if introduced is not None and introduced <= version < boundary:
                    return True
                introduced = None
            elif event_type == "last_affected":
                if introduced is not None and introduced <= version <= boundary:
                    return True
                introduced = None
            elif event_type == "limit":
                if introduced is not None and introduced <= version < boundary:
                    return True
                introduced = None

        return introduced is not None and introduced <= version

    except (InvalidVersion, TypeError, ValueError):
        return None


def _range_result(version: str, affected) -> bool | None:
    """Combine the evaluable ranges for one affected-package entry."""
    if not affected.ranges:
        return None

    results = []
    for item in affected.ranges:
        # Only PyPI ECOSYSTEM ranges are evaluated here.
        if item.type == "ECOSYSTEM":
            results.append(_in_pypi_range(version, item.events))
        else:
            results.append(None)

    if any(result is True for result in results):
        return True
    if results and all(result is False for result in results):
        return False
    return None


def transform_advisories(
    advisories: Iterable[tuple[OsvVuln, int | None]],
    releases: pd.DataFrame | None = None,
) -> dict[str, pd.DataFrame]:
    """Transform OSV advisories and their affected-package information.

    The frames contain natural keys only. Database surrogate IDs are resolved
    later by the loader.
    """
    frames = _empty_frames()

    vulnerabilities = []
    aliases = set()
    severities = set()

    affected_packages = []
    affected_ranges = []
    affected_events = []
    affected_versions = []
    affected_releases = []

    for advisory, raw_object_id in advisories:
        row = {
            "vulnerability_id": advisory.id,
            "published_at": advisory.published,
            "modified_at": advisory.modified,
            "withdrawn_at": advisory.withdrawn,
            "summary": advisory.summary,
            "details": advisory.details,
            "schema_version": advisory.schema_version,
            "dates_out_of_order": advisory.dates_out_of_order,
            "raw_object_id": raw_object_id,
        }
        row["content_hash"] = content_hash(row, VULNERABILITY_COLUMNS[:-1])
        vulnerabilities.append(row)

        aliases.update((advisory.id, alias) for alias in advisory.aliases)
        severities.update(
            (advisory.id, item.type, item.score, item.source)
            for item in advisory.severity
        )

        for entry_index, affected in enumerate(advisory.affected):
            # This dataset currently covers PyPI packages.
            if affected.package is None:
                continue
            if affected.package.ecosystem.casefold() != "pypi":
                continue

            package_name = canonicalize_name(affected.package.name)

            affected_packages.append({
                "vulnerability_id": advisory.id,
                "package_name": package_name,
                "entry_index": entry_index,
            })

            for range_index, range_item in enumerate(affected.ranges):
                affected_ranges.append({
                    "vulnerability_id": advisory.id,
                    "entry_index": entry_index,
                    "range_index": range_index,
                    "range_type": range_item.type,
                    "repo": range_item.repo,
                })

                for event_order, event in enumerate(range_item.events):
                    affected_events.append({
                        "vulnerability_id": advisory.id,
                        "entry_index": entry_index,
                        "range_index": range_index,
                        "event_order": event_order,
                        "event_type": event.event_type,
                        "version_string": event.version_string,
                    })

            for version in affected.versions:
                affected_versions.append({
                    "vulnerability_id": advisory.id,
                    "entry_index": entry_index,
                    "version": version,
                })

            # Match against the release rows supplied by the caller.
            if releases is None or releases.empty:
                continue

            package_releases = releases.loc[
                releases["canonical_name"] == package_name,
                ["canonical_name", "version"],
            ].drop_duplicates()

            enumerated_versions = set(affected.versions)

            for release in package_releases.itertuples(index=False):
                in_range = _range_result(release.version, affected)
                in_enumerated = (
                    release.version in enumerated_versions
                    if enumerated_versions
                    else None
                )

                # The database CHECK requires at least one non-NULL result.
                if in_range is None and in_enumerated is None:
                    continue

                affected_releases.append({
                    "canonical_name": release.canonical_name,
                    "version": release.version,
                    "vulnerability_id": advisory.id,
                    "entry_index": entry_index,
                    "in_range": in_range,
                    "in_enumerated": in_enumerated,
                })

    frames["vulnerability"] = pd.DataFrame(
        vulnerabilities, columns=VULNERABILITY_COLUMNS
    )
    frames["vulnerability_alias"] = pd.DataFrame(
        sorted(aliases), columns=ALIAS_COLUMNS
    )
    frames["vulnerability_severity"] = pd.DataFrame(
        sorted(severities), columns=SEVERITY_COLUMNS
    )

    frames["affected_package"] = pd.DataFrame(
        affected_packages, columns=AFFECTED_PACKAGE_COLUMNS
    ).drop_duplicates()
    frames["affected_range"] = pd.DataFrame(
        affected_ranges, columns=AFFECTED_RANGE_COLUMNS
    ).drop_duplicates()
    frames["affected_event"] = pd.DataFrame(
        affected_events, columns=AFFECTED_EVENT_COLUMNS
    ).drop_duplicates()
    frames["affected_version"] = pd.DataFrame(
        affected_versions, columns=AFFECTED_VERSION_COLUMNS
    ).drop_duplicates()
    frames["affected_release"] = pd.DataFrame(
        affected_releases, columns=AFFECTED_RELEASE_COLUMNS
    ).drop_duplicates()

    return frames


def transform_osv(
    payload: dict,
    *,
    raw_object_id: int | None = None,
    releases: pd.DataFrame | None = None,
) -> tuple[dict[str, pd.DataFrame], list[dict]]:
    """Validate an OSV page and transform every valid advisory in it."""
    from pipeline.validate.osv import validate_osv_page

    result = validate_osv_page(payload, raw_object_id)
    return (
        transform_advisories(
            ((advisory, raw_object_id) for advisory in result.vulns),
            releases,
        ),
        result.quarantine,
    )
