"""OSV response transformation and release exposure evaluation."""

from __future__ import annotations

from collections.abc import Mapping

import pandas as pd
from packaging.utils import canonicalize_name
from pydantic import ValidationError

from pipeline.contracts.models import OSVResponse
from pipeline.contracts.records import QuarantineRecord, quarantine_from_error
from pipeline.transform.common import content_hash, utc_datetime
from pipeline.transform.ranges import evaluate_ranges


def transform_osv(
    payload: Mapping, *, raw_object_id: int | None = None,
    releases: pd.DataFrame | None = None,
) -> tuple[dict[str, pd.DataFrame], list[QuarantineRecord]]:
    try:
        advisory = OSVResponse.model_validate(payload)
    except (ValidationError, TypeError, ValueError) as error:
        return {}, [quarantine_from_error(error, raw_object_id=raw_object_id)]

    dates_out_of_order = bool(
        advisory.published and advisory.published > advisory.modified
        or advisory.withdrawn and advisory.withdrawn < advisory.published
    )
    vulnerability = {
        "vulnerability_id": advisory.id,
        "published_at": utc_datetime(advisory.published),
        "modified_at": utc_datetime(advisory.modified),
        "withdrawn_at": utc_datetime(advisory.withdrawn),
        "summary": advisory.summary,
        "details": advisory.details,
        "schema_version": advisory.schema_version,
        "dates_out_of_order": dates_out_of_order,
        "raw_object_id": raw_object_id,
    }
    vulnerability["content_hash"] = content_hash(
        vulnerability, tuple(k for k in vulnerability if k != "content_hash")
    )
    affected_packages, affected_ranges, affected_events, affected_versions = [], [], [], []
    severities = [
        {"vulnerability_id": advisory.id, "severity_type": item.type,
         "vector": item.score, "origin": item.source}
        for item in advisory.severity
    ]
    for entry_index, affected in enumerate(advisory.affected):
        package_name = canonicalize_name(affected.package.package)
        affected_packages.append({
            "vulnerability_id": advisory.id, "package_name": package_name,
            "package_id": None, "entry_index": entry_index,
        })
        for version in affected.versions:
            affected_versions.append({
                "vulnerability_id": advisory.id, "entry_index": entry_index, "version": version,
            })
        for range_index, range_item in enumerate(affected.ranges):
            affected_ranges.append({
                "vulnerability_id": advisory.id, "entry_index": entry_index,
                "range_index": range_index, "range_type": range_item.type, "repo": range_item.repo,
            })
            for event_order, event in enumerate(range_item.events):
                event_data = event.model_dump(exclude_none=True)
                event_type, version = next(iter(event_data.items()))
                affected_events.append({
                    "vulnerability_id": advisory.id, "entry_index": entry_index,
                    "range_index": range_index, "event_order": event_order,
                    "event_type": event_type, "version_string": version,
                })
    frames = {
        "vulnerability": pd.DataFrame([vulnerability]),
        "vulnerability_alias": pd.DataFrame(
            [{"vulnerability_id": advisory.id, "alias": alias} for alias in advisory.aliases]
        ),
        "vulnerability_severity": pd.DataFrame(severities),
        "affected_package": pd.DataFrame(affected_packages),
        "affected_range": pd.DataFrame(affected_ranges),
        "affected_event": pd.DataFrame(affected_events),
        "affected_version": pd.DataFrame(affected_versions),
    }
    if releases is not None and not releases.empty:
        exposure = []
        for row in releases.to_dict("records"):
            for entry_index, affected in enumerate(advisory.affected):
                if canonicalize_name(row["canonical_name"]) != canonicalize_name(affected.package.package):
                    continue
                ranges = [item.model_dump() for item in affected.ranges]
                exposure.append({
                    "canonical_name": row["canonical_name"], "version": row["version"],
                    "vulnerability_id": advisory.id, "entry_index": entry_index,
                    "in_range": evaluate_ranges(row["version"], ranges),
                    "in_enumerated": row["version"] in affected.versions or None,
                })
        frames["affected_release"] = pd.DataFrame(exposure)
    return frames, []
