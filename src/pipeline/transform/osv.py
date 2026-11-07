"""Transform validated OSV advisories into canonical vulnerability frames."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd

from pipeline.transform.common import content_hash
from pipeline.validate.osv import OsvVuln

VULNERABILITY_COLUMNS = (
    "vulnerability_id", "published_at", "modified_at", "withdrawn_at", "summary", "details",
    "schema_version", "dates_out_of_order", "raw_object_id", "content_hash",
)
ALIAS_COLUMNS = ("vulnerability_id", "alias")
SEVERITY_COLUMNS = ("vulnerability_id", "severity_type", "vector", "origin")


def _empty_frames() -> dict[str, pd.DataFrame]:
    return {
        "vulnerability": pd.DataFrame(columns=VULNERABILITY_COLUMNS),
        "vulnerability_alias": pd.DataFrame(columns=ALIAS_COLUMNS),
        "vulnerability_severity": pd.DataFrame(columns=SEVERITY_COLUMNS),
    }


def transform_advisories(
    advisories: Iterable[tuple[OsvVuln, int | None]],
    releases: pd.DataFrame | None = None,
) -> dict[str, pd.DataFrame]:
    vulnerabilities, aliases, severities = [], set(), set()
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
            (advisory.id, item.type, item.score, item.source) for item in advisory.severity
        )
    frames = {
        "vulnerability": pd.DataFrame(vulnerabilities, columns=VULNERABILITY_COLUMNS),
        "vulnerability_alias": pd.DataFrame(sorted(aliases), columns=ALIAS_COLUMNS),
        "vulnerability_severity": pd.DataFrame(sorted(severities), columns=SEVERITY_COLUMNS),
    }
    return frames


def transform_osv(
    payload: dict, *, raw_object_id: int | None = None,
    releases: pd.DataFrame | None = None,
) -> tuple[dict[str, pd.DataFrame], list[dict]]:
    """Validate an OSV page and transform every valid advisory in it."""
    from pipeline.validate.osv import validate_osv_page

    result = validate_osv_page(payload, raw_object_id)
    return transform_advisories(
        ((advisory, raw_object_id) for advisory in result.vulns), releases
    ), result.quarantine
