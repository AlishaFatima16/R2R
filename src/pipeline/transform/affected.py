"""Transform OSV 'affected' entries into the affected_* frames the loader expects.

Frames carry natural keys only: (vulnerability_id, entry_index) identifies an affected
entry, never a surrogate id. Only entries for PyPI packages are kept.
"""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd
from packaging.utils import canonicalize_name

from pipeline.transform.ranges import evaluate_ranges
from pipeline.validate.osv import OsvVuln

PACKAGE_COLUMNS = ("vulnerability_id", "entry_index", "package_name")
RANGE_COLUMNS = ("vulnerability_id", "entry_index", "range_index", "range_type", "repo")
EVENT_COLUMNS = (
    "vulnerability_id", "entry_index", "range_index", "event_order", "event_type",
    "version_string",
)
VERSION_COLUMNS = ("vulnerability_id", "entry_index", "version")
RELEASE_COLUMNS = (
    "canonical_name", "version", "vulnerability_id", "entry_index", "in_range", "in_enumerated",
)


def _frame(rows: list[dict], columns: tuple[str, ...], key: tuple[str, ...]) -> pd.DataFrame:
    frame = pd.DataFrame(rows, columns=columns)
    return frame.drop_duplicates(subset=list(key), keep="last").reset_index(drop=True)


def transform_affected(
    advisories: Iterable[OsvVuln], releases: pd.DataFrame | None = None
) -> dict[str, pd.DataFrame]:
    """Build affected_package/range/event/version/release frames for PyPI entries."""
    versions_by_package: dict[str, list[str]] = {}
    if releases is not None and not releases.empty:
        for name, version in zip(releases["canonical_name"], releases["version"], strict=True):
            versions_by_package.setdefault(name, []).append(version)

    packages, ranges, events, versions, release_rows = [], [], [], [], []
    for advisory in advisories:
        for entry_index, entry in enumerate(advisory.affected):
            if entry.package is None or entry.package.ecosystem != "PyPI":
                continue
            name = canonicalize_name(entry.package.name)
            packages.append(
                {"vulnerability_id": advisory.id, "entry_index": entry_index,
                 "package_name": name}
            )
            usable_ranges = []
            for range_index, item in enumerate(entry.ranges):
                ranges.append(
                    {"vulnerability_id": advisory.id, "entry_index": entry_index,
                     "range_index": range_index, "range_type": item.type,
                     "repo": item.repo if item.type == "GIT" else None}
                )
                for event_order, event in enumerate(item.events):
                    events.append(
                        {"vulnerability_id": advisory.id, "entry_index": entry_index,
                         "range_index": range_index, "event_order": event_order,
                         "event_type": event.event_type, "version_string": event.version_string}
                    )
                if item.type != "GIT":  # commit hashes are not versions
                    usable_ranges.append(
                        {"events": [{e.event_type: e.version_string} for e in item.events]}
                    )
            listed = set(entry.versions)
            for version in sorted(listed):
                versions.append(
                    {"vulnerability_id": advisory.id, "entry_index": entry_index,
                     "version": version}
                )
            for version in versions_by_package.get(name, []):
                in_range = evaluate_ranges(version, usable_ranges) if usable_ranges else None
                in_enumerated = (version in listed) if listed else None
                if in_range is None and in_enumerated is None:
                    continue  # nothing is known about this release; the schema forbids it
                release_rows.append(
                    {"canonical_name": name, "version": version,
                     "vulnerability_id": advisory.id, "entry_index": entry_index,
                     "in_range": in_range, "in_enumerated": in_enumerated}
                )

    frames = {
        "affected_package": _frame(packages, PACKAGE_COLUMNS, PACKAGE_COLUMNS[:2]),
        "affected_range": _frame(ranges, RANGE_COLUMNS, RANGE_COLUMNS[:3]),
        "affected_event": _frame(events, EVENT_COLUMNS, EVENT_COLUMNS[:4]),
        "affected_version": _frame(versions, VERSION_COLUMNS, VERSION_COLUMNS),
        "affected_release": _frame(release_rows, RELEASE_COLUMNS, RELEASE_COLUMNS[:4]),
    }
    return {table: frame for table, frame in frames.items() if not frame.empty}
