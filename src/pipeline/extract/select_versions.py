"""Choose which releases get their own request (the per-release JSON with requires_dist).

The project JSON lists every release but only the latest one's dependencies. Fetching all
of them for every package is too many requests, so we take:
    - the N most recent releases (by upload time), and
    - every release named in an OSV introduced / fixed / last_affected event,
      so the advisory ranges can be matched to real releases.
"""

from __future__ import annotations

NAMED_EVENTS = ("introduced", "fixed", "last_affected")


def upload_times(project_body: dict) -> dict[str, str]:
    """version -> the latest upload time string of its files ('' if it has no files)."""
    releases = project_body.get("releases") or {}
    times = {}
    for version, files in releases.items():
        stamps = [f.get("upload_time_iso_8601") or "" for f in files or [] if isinstance(f, dict)]
        times[version] = max(stamps, default="")
    return times


def versions_named_by_osv(osv_bodies: list[dict]) -> set[str]:
    named = set()
    for body in osv_bodies:
        for vuln in (body or {}).get("vulns", []):
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    if rng.get("type") == "GIT":
                        continue  # commit hashes, not release versions
                    for event in rng.get("events", []):
                        for key in NAMED_EVENTS:
                            if event.get(key):
                                named.add(event[key])
    return named


def select_versions(project_body: dict, osv_bodies: list[dict], limit: int = 30) -> list[str]:
    """Versions to fetch, oldest first. Only versions that exist on PyPI are returned."""
    times = upload_times(project_body)
    # ISO-8601 UTC strings sort in time order; releases without files sort as oldest.
    recent = sorted(times, key=lambda version: (times[version], version), reverse=True)[:limit]
    wanted = set(recent) | (versions_named_by_osv(osv_bodies) & set(times))
    return sorted(wanted, key=lambda version: (times[version], version))
