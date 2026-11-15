"""Batch transform plug-in used by :mod:`pipeline.orchestrate`."""

from __future__ import annotations

from collections import defaultdict

import pandas as pd
from packaging.utils import canonicalize_name

from pipeline.quality.rules import quality_frame
from pipeline.transform.common import content_hash
from pipeline.transform.depsdev import transform_dependencies
from pipeline.transform.osv import transform_advisories
from pipeline.transform.pypi import transform_project


def transform(batch) -> object:
    """Transform an orchestrator ValidatedBatch into loader-compatible frames."""
    projects = {
        canonicalize_name(item.name): item
        for item in batch.projects
    }
    versions: dict[str, dict[str, tuple[object, int | None]]] = defaultdict(dict)
    for item in batch.versions:
        versions[canonicalize_name(item.name)][item.version] = (item.release, item.raw_object_id)

    combined: dict[str, list[pd.DataFrame]] = defaultdict(list)
    for name, item in projects.items():
        if name not in batch.seed:
            continue
        combined_frames = transform_project(
            item.project,
            versions.get(name, {}),
            seed_tier=batch.seed[name],
            project_raw_object_id=item.raw_object_id,
        )
        for table, frame in combined_frames.items():
            combined[table].append(frame)

    frames = {
        table: pd.concat(parts, ignore_index=True)
        for table, parts in combined.items()
    }
    package_frame = frames.get("package", pd.DataFrame())
    target_names = set()
    if "dependency" in frames:
        target_names = set(frames["dependency"]["target_name"].dropna())
    resolved = _resolved_nodes(batch, frames.get("release"))
    if not resolved.empty:
        frames["resolved_node"] = resolved
        target_names |= set(resolved["canonical_name"])
    existing = set(package_frame.get("canonical_name", pd.Series(dtype=str)))
    stubs = [
        {
            "canonical_name": name,
            "display_name": None,
            "in_seed": False,
            "seed_tier": None,
            "summary": None,
            "repo_url": None,
            "license_raw": None,
            "latest_version": None,
            "last_serial": None,
            "raw_object_id": None,
            "content_hash": None,
        }
        for name in sorted(target_names - existing)
    ]
    if stubs:
        stub_frame = pd.DataFrame(stubs, columns=package_frame.columns)
        stub_frame["content_hash"] = [
            content_hash(row, package_frame.columns[:-1])
            for row in stub_frame.to_dict("records")
        ]
        frames["package"] = pd.concat([package_frame, stub_frame], ignore_index=True)

    advisory_items = [
        (advisory, page.raw_object_id)
        for page in batch.osv_pages
        for advisory in page.vulns
    ]
    frames.update(transform_advisories(advisory_items, frames.get("release")))
    from pipeline.orchestrate import TransformResult

    frames = _dedupe(frames)
    quality = quality_frame(frames)
    if not quality.empty:
        frames["data_quality_result"] = quality
    return TransformResult(frames=frames)


def _resolved_nodes(batch, releases):
    """Depth of every resolved dependency, from the deps.dev graphs saved for each release."""
    parts = []
    for item in getattr(batch, "depsdev_graphs", []):
        if item.graph is None:
            continue
        try:
            parts.append(
                transform_dependencies(item.graph, root_name=item.name, root_version=item.version)
            )
        except ValueError:
            continue  # error graph or root mismatch: nothing trustworthy to load
    parts = [part for part in parts if not part.empty]
    if not parts:
        return pd.DataFrame()
    frame = pd.concat(parts, ignore_index=True)
    if releases is None or releases.empty:
        return pd.DataFrame()
    roots = releases[["canonical_name", "version"]].rename(
        columns={"canonical_name": "root_canonical_name", "version": "root_version"}
    )
    return frame.merge(roots, on=["root_canonical_name", "root_version"], how="inner")


def _dedupe(frames):
    """Drop repeated rows by natural key: one advisory can arrive via several packages."""
    from pipeline.load.tables import LOAD_ORDER

    for spec in LOAD_ORDER:
        frame = frames.get(spec.table)
        if frame is None or frame.empty:
            continue
        keys = list(spec.key)
        if not set(keys) <= set(frame.columns):
            continue
        if "modified_at" in frame.columns:
            frame = frame.sort_values("modified_at", kind="stable", na_position="first")
        frames[spec.table] = frame.drop_duplicates(subset=keys, keep="last").reset_index(drop=True)
    return frames


__all__ = ["transform"]
