"""Export the dashboard's JSON files from PostgreSQL.

    $env:DATABASE_URL = "postgresql://user:password@host:5432/r2r"      # PowerShell
    export DATABASE_URL=postgresql://user:password@host:5432/r2r        # bash
    python scripts/export_dashboard_data.py
    python scripts/export_dashboard_data.py --out dashboard/data --as-of 2026-11-15T00:00:00Z

The connection string is read from the DATABASE_URL environment variable (or from a local .env
file) and is never written to disk. The script only reads: it queries the views in sql/views/
and the point-in-time function vulnerabilities_as_of(), plus a few base tables the views do not
expose (aliases, severities, range events, quarantine, data quality, run history).

Output (all under --out, default dashboard/data):
    overview.json            headline numbers and the four overview charts (tier A only)
    packages.json            one row per seed package, for the explorer table
    packages/<name>.json     one file per package: releases, advisory windows, dependencies
    advisories.json          one row per advisory record, for search and the advisory page
    pipeline.json            the latest run: stage counts, quarantine, data quality, run history

The shaping code (build_files) is pure: it takes plain rows, so tests and the sample-data builder
call it without a database. Every file carries generated_at, run_id and is_sample.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
from collections import defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from packaging.version import InvalidVersion, Version

SCHEMA_VERSION = 1
DEFAULT_REPO_URL = "https://github.com/AlishaFatima16/R2R"
LEVELS = ("low", "medium", "high", "critical")
REASON_CODES = (
    "missing_field",
    "type_error",
    "invalid_timestamp",
    "malformed_identifier",
    "unexpected_structure",
    "empty_body",
    "duplicate_conflict",
    "invalid_value",
)
TABLES = (
    "package",
    "release",
    "dependency",
    "vulnerability",
    "vulnerability_alias",
    "affected_package",
    "affected_release",
    "resolved_node",
    "raw_object",
    "quarantine",
    "data_quality_result",
)
FIX_BINS = (
    ("under 1 week", 0, 7),
    ("1-4 weeks", 7, 30),
    ("1-3 months", 30, 90),
    ("3-6 months", 90, 180),
    ("6-12 months", 180, 365),
    ("1-2 years", 365, 730),
    ("2-5 years", 730, 1826),
    ("over 5 years", 1826, math.inf),
)
MAX_DEPENDENCIES = 300

# ---------------------------------------------------------------------------------- queries

QUERIES: dict[str, str] = {
    "run_latest": """
        SELECT run_id, started_at, finished_at, status, git_commit, config_hash, notes
        FROM pipeline_run ORDER BY started_at DESC, run_id DESC LIMIT 1
    """,
    "run_data": """
        SELECT run_id, started_at, finished_at, status, git_commit, config_hash, notes
        FROM pipeline_run WHERE status = 'succeeded'
        ORDER BY started_at DESC, run_id DESC LIMIT 1
    """,
    "recent_runs": """
        SELECT run_id, started_at, finished_at, status, git_commit, notes
        FROM pipeline_run ORDER BY started_at DESC, run_id DESC LIMIT 8
    """,
    "packages": """
        SELECT p.package_id, p.canonical_name, p.display_name, p.seed_tier, p.summary,
               p.repo_url, p.license_raw, p.latest_version, p.last_serial
        FROM package AS p
        WHERE p.in_seed
        ORDER BY p.canonical_name
    """,
    "releases": """
        SELECT h.package_id, h.release_id, h.version, h.version_valid, h.version_rank,
               h.is_prerelease, h.is_dev, h.uploaded_at, h.yanked, h.requires_python,
               h.deps_fetched
        FROM v_package_release_history AS h
        WHERE h.in_seed AND h.release_id IS NOT NULL
        ORDER BY h.package_id, h.version_rank NULLS LAST, h.uploaded_at
    """,
    # Advisories in force at export time: published, and not withdrawn (see sql/functions).
    "advisories": """
        SELECT pv.package_id, pv.package_name, pv.entry_index, pv.vulnerability_id,
               pv.published_at, pv.modified_at, pv.withdrawn_at, pv.summary,
               pv.dates_out_of_order
        FROM v_package_vulnerabilities AS pv
        JOIN vulnerabilities_as_of(%(as_of)s) AS v ON v.vulnerability_id = pv.vulnerability_id
        JOIN package AS p ON p.package_id = pv.package_id
        WHERE p.in_seed
        ORDER BY pv.vulnerability_id, pv.package_id, pv.entry_index
    """,
    "advisories_excluded": """
        SELECT COUNT(DISTINCT pv.vulnerability_id) AS n
        FROM v_package_vulnerabilities AS pv
        JOIN package AS p ON p.package_id = pv.package_id
        WHERE p.in_seed
          AND pv.vulnerability_id NOT IN (
              SELECT vulnerability_id FROM vulnerabilities_as_of(%(as_of)s)
          )
    """,
    "aliases": "SELECT vulnerability_id, alias FROM vulnerability_alias",
    "severities": (
        "SELECT vulnerability_id, severity_type, vector, origin FROM vulnerability_severity"
    ),
    "events": """
        SELECT ap.vulnerability_id, ap.package_id, ap.entry_index, ar.range_index,
               ar.range_type, ae.event_order, ae.event_type, ae.version_string
        FROM affected_package AS ap
        JOIN affected_range AS ar ON ar.affected_id = ap.affected_id
        JOIN affected_event AS ae ON ae.range_id = ar.range_id
        WHERE ap.package_id IS NOT NULL
        ORDER BY ap.vulnerability_id, ap.package_id, ap.entry_index, ar.range_index,
                 ae.event_order
    """,
    "exposure": """
        SELECT rv.release_id, rv.package_id, rv.vulnerability_id, rv.in_range, rv.in_enumerated
        FROM v_release_vulnerabilities AS rv
    """,
    "dependencies": """
        SELECT d.release_id, d.package_id, d.target_package_name, d.raw_requirement,
               d.requirement_valid, d.specifier, d.marker, d.extras, d.is_extra_only,
               d.is_conditional
        FROM v_release_dependencies AS d
        WHERE d.release_id = ANY(%(release_ids)s) AND d.dependency_id IS NOT NULL
    """,
    "resolved": """
        SELECT root_release_id, dependency_package_name, node_version, relation, depth
        FROM v_resolved_dependency_depth
        WHERE root_release_id = ANY(%(release_ids)s)
        ORDER BY root_release_id, depth, dependency_package_name
    """,
    "raw_by_source": """
        SELECT s.name AS source, COUNT(*) AS responses,
               COUNT(*) FILTER (WHERE ro.http_status = 200) AS ok,
               COUNT(*) FILTER (WHERE ro.http_status = 404) AS not_found,
               COUNT(*) FILTER (WHERE ro.http_status NOT IN (200, 404)) AS other_status
        FROM raw_object AS ro JOIN source AS s ON s.source_id = ro.source_id
        WHERE ro.run_id = %(run_id)s
        GROUP BY s.name ORDER BY s.name
    """,
    "quarantine_counts": """
        SELECT stage, reason_code, COUNT(*) AS n
        FROM quarantine WHERE run_id = %(run_id)s
        GROUP BY stage, reason_code ORDER BY n DESC, reason_code
    """,
    "quarantine_distinct": """
        SELECT COUNT(DISTINCT raw_object_id) AS n
        FROM quarantine WHERE run_id = %(run_id)s AND stage = 'validate'
    """,
    "quarantine_samples": """
        SELECT quarantine_id, raw_object_id, stage, reason_code, field_path,
               LEFT(message, 240) AS message
        FROM quarantine WHERE run_id = %(run_id)s
        ORDER BY quarantine_id DESC LIMIT 25
    """,
    "dq_results": """
        SELECT check_name, dimension, table_name, metric_value, threshold, passed
        FROM data_quality_result WHERE run_id = %(run_id)s
        ORDER BY passed, dimension, check_name, table_name
    """,
    "table_counts": " UNION ALL ".join(
        f"SELECT '{name}' AS table_name, COUNT(*) AS n FROM {name}" for name in TABLES
    ),
}


def fetch_all(conn, sql: str, params: dict | None = None) -> list[dict]:
    """Run one query and return its rows as dicts. Works with psycopg and with test stubs."""
    cursor = conn.execute(sql, params or {})
    columns = [getattr(col, "name", None) or col[0] for col in cursor.description]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def fetch_dataset(conn, as_of: datetime) -> dict:
    """Read everything the dashboard needs. Returns plain rows keyed by purpose."""
    q = QUERIES
    data: dict = {"as_of": as_of}
    latest = fetch_all(conn, q["run_latest"])
    data_run = fetch_all(conn, q["run_data"]) or latest
    data["run_latest"] = latest[0] if latest else None
    data["run"] = data_run[0] if data_run else None
    data["recent_runs"] = fetch_all(conn, q["recent_runs"])
    data["packages"] = fetch_all(conn, q["packages"])
    data["releases"] = fetch_all(conn, q["releases"])
    params = {"as_of": as_of}
    data["advisories"] = fetch_all(conn, q["advisories"], params)
    excluded = fetch_all(conn, q["advisories_excluded"], params)
    data["advisories_excluded"] = int(excluded[0]["n"]) if excluded else 0
    data["aliases"] = fetch_all(conn, q["aliases"])
    data["severities"] = fetch_all(conn, q["severities"])
    data["events"] = fetch_all(conn, q["events"])
    data["exposure"] = fetch_all(conn, q["exposure"])

    latest_ids = sorted(latest_release_ids(data["packages"], data["releases"]).values())
    ids = {"release_ids": latest_ids}
    data["dependencies"] = fetch_all(conn, q["dependencies"], ids)
    data["resolved"] = fetch_all(conn, q["resolved"], ids)

    run_id = (data["run_latest"] or {}).get("run_id")
    pipeline: dict = {"run_id": run_id, "table_counts": fetch_all(conn, q["table_counts"])}
    if run_id is not None:
        rid = {"run_id": run_id}
        distinct = fetch_all(conn, q["quarantine_distinct"], rid)
        pipeline.update(
            raw_by_source=fetch_all(conn, q["raw_by_source"], rid),
            quarantine_counts=fetch_all(conn, q["quarantine_counts"], rid),
            quarantine_distinct=int(distinct[0]["n"]) if distinct else 0,
            quarantine_samples=fetch_all(conn, q["quarantine_samples"], rid),
            dq_results=fetch_all(conn, q["dq_results"], rid),
        )
    data["pipeline"] = pipeline
    return data


# ------------------------------------------------------------------------------- small helpers


def as_dt(value) -> datetime | None:
    """datetime or ISO string -> aware UTC datetime. Anything missing becomes None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        text = value.strip()
        value = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def iso(value) -> str | None:
    moment = as_dt(value)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def num(value):
    """Decimal and numpy-ish numbers -> plain int or float; None stays None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value


def trim(text, limit: int) -> str | None:
    if text is None:
        return None
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def parse_version(text) -> Version | None:
    try:
        return Version(str(text))
    except InvalidVersion:
        return None


def median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def latest_release_ids(packages: list[dict], releases: list[dict]) -> dict[int, int]:
    """package_id -> release_id of the package's latest release."""
    by_package: dict[int, list[dict]] = defaultdict(list)
    for row in releases:
        by_package[row["package_id"]].append(row)
    result = {}
    for package in packages:
        rows = by_package.get(package["package_id"], [])
        if not rows:
            continue
        match = [r for r in rows if r["version"] == package.get("latest_version")]
        ranked = [r for r in rows if r.get("version_rank") is not None]
        if match:
            chosen = match[0]
        elif ranked:
            chosen = max(ranked, key=lambda r: r["version_rank"])
        else:
            chosen = max(rows, key=lambda r: as_dt(r.get("uploaded_at")) or datetime.min.replace(
                tzinfo=UTC))
        result[package["package_id"]] = chosen["release_id"]
    return result


# ------------------------------------------------------------------------------------- CVSS v3

_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_score(vector: str | None) -> float | None:
    """CVSS v3.x base score from a vector string, or None if it is not a valid v3 vector."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        privileges = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[
            metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min(1.08 * total if scope_changed else total, 10.0))


def level_for(score: float | None) -> str | None:
    if score is None or score <= 0:
        return None
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def severity_for(rows: list[dict]) -> dict:
    """Pick the severity of one advisory: the CVSS v3 score if present, else just the vector."""
    best = {"level": None, "score": None, "vector": None, "type": None}
    for row in rows:
        vector = row.get("vector")
        score = cvss3_score(vector) if row.get("severity_type") == "CVSS_V3" else None
        if score is not None and (best["score"] is None or score > best["score"]):
            best = {"level": level_for(score), "score": score, "vector": vector, "type": "CVSS_V3"}
    if best["type"] is None and rows:
        other = rows[0]
        best["vector"] = other.get("vector")
        best["type"] = other.get("severity_type")
    return best


def worse(a: str | None, b: str | None) -> str | None:
    """The more severe of two levels (None counts as unrated)."""
    rank = {None: -1, "u": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return a if rank.get(a, -1) >= rank.get(b, -1) else b


# --------------------------------------------------------------------------------- alias groups


def alias_groups(vuln_ids: list[str], aliases: dict[str, list[str]]) -> dict[str, dict]:
    """Merge advisory records that are the same issue (shared CVE/GHSA/PYSEC alias).

    Returns vulnerability_id -> {"label", "ids", "aliases"}. A GHSA record and the PYSEC record
    for the same CVE are one issue, so counting records would double count it.
    """
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    for vid in vuln_ids:
        find(vid)
        for alias in aliases.get(vid, []):
            union(vid, alias)
    members: dict[str, set[str]] = defaultdict(set)
    for node in list(parent):
        members[find(node)].add(node)
    known = set(vuln_ids)
    result = {}
    for nodes in members.values():
        ids = sorted(nodes & known)
        if not ids:
            continue
        cves = sorted(n for n in nodes if n.startswith("CVE-"))
        label = cves[0] if cves else ids[0]
        others = sorted(nodes - set(ids))
        group = {"label": label, "ids": ids, "aliases": others}
        for vid in ids:
            result[vid] = group
    return result


# ---------------------------------------------------------------------------- exposure windows


def _windows_from_events(events: list[dict]) -> list[dict]:
    """OSV events of one advisory and package -> [{"from", "to", "kind"}], skipping GIT ranges."""
    ranges: dict[tuple, list[dict]] = defaultdict(list)
    for event in events:
        if event.get("range_type") == "GIT":
            continue
        ranges[(event["entry_index"], event["range_index"])].append(event)
    windows = []
    for key in sorted(ranges):
        start = None
        for event in sorted(ranges[key], key=lambda e: e["event_order"]):
            kind, version = event["event_type"], event["version_string"]
            if kind == "introduced":
                start = version
            else:
                kind_name = "fixed" if kind == "fixed" else kind
                windows.append({"from": start if start is not None else "0",
                                "to": version, "kind": kind_name})
                start = None
        if start is not None:
            windows.append({"from": start, "to": None, "kind": "open"})
    return windows


def _resolve_window(window: dict, ordered: list[tuple[Version, dict]], first_time, as_of) -> dict:
    """Attach dates to a window using the package's own release dates."""
    out = dict(window)
    origin = window["from"] in ("0", "", "*")
    start_time = first_time
    if not origin:
        lower = parse_version(window["from"])
        start_time = None
        if lower is not None:
            for parsed, release in ordered:
                if parsed >= lower and as_dt(release.get("uploaded_at")):
                    start_time = as_dt(release["uploaded_at"])
                    break
    end_time = None
    if window["kind"] == "open":
        end_time = as_of
    else:
        upper = parse_version(window["to"])
        for parsed, release in ordered:
            if upper is not None and parsed == upper:
                end_time = as_dt(release.get("uploaded_at"))
                break
    days = None
    if window["kind"] in ("fixed", "limit") and start_time and end_time and not origin:
        span = (end_time - start_time).total_seconds() / 86400
        days = round(span, 1) if span >= 0 else None
    out.update(start=iso(start_time), end=iso(end_time), origin=origin, days=days)
    return out


def _runs(indexes: list[int]) -> list[list[int]]:
    """[1,2,3,7,8] -> [[1,3],[7,8]]"""
    runs: list[list[int]] = []
    for index in sorted(set(indexes)):
        if runs and index == runs[-1][1] + 1:
            runs[-1][1] = index
        else:
            runs.append([index, index])
    return runs


# ------------------------------------------------------------------------------------ shaping


def build_files(data: dict, *, is_sample: bool, repo_url: str = DEFAULT_REPO_URL) -> dict:
    """Turn plain rows into the dashboard's JSON files: {relative path: payload}."""
    as_of = as_dt(data["as_of"])
    run = data.get("run") or {}
    meta = {
        "schema": SCHEMA_VERSION,
        "generated_at": iso(as_of),
        "run_id": run.get("run_id"),
        "is_sample": bool(is_sample),
    }
    packages = data["packages"]
    by_id = {p["package_id"]: p for p in packages}

    releases_by_pkg: dict[int, list[dict]] = defaultdict(list)
    for row in data["releases"]:
        if row["package_id"] in by_id:
            releases_by_pkg[row["package_id"]].append(row)
    for rows in releases_by_pkg.values():
        rows.sort(key=lambda r: (r.get("version_rank") is None, r.get("version_rank") or 0,
                                 iso(r.get("uploaded_at")) or ""))

    # advisory records ---------------------------------------------------------------
    aliases: dict[str, list[str]] = defaultdict(list)
    for row in data["aliases"]:
        aliases[row["vulnerability_id"]].append(row["alias"])
    severity_rows: dict[str, list[dict]] = defaultdict(list)
    for row in data["severities"]:
        severity_rows[row["vulnerability_id"]].append(row)

    records: dict[str, dict] = {}
    pkg_records: dict[int, set[str]] = defaultdict(set)
    for row in data["advisories"]:
        if row["package_id"] not in by_id:
            continue
        record = records.setdefault(row["vulnerability_id"], {
            "id": row["vulnerability_id"],
            "published": iso(row.get("published_at")),
            "modified": iso(row.get("modified_at")),
            "summary": trim(row.get("summary"), 300),
            "packages": set(),
        })
        record["packages"].add(row["package_id"])
        pkg_records[row["package_id"]].add(row["vulnerability_id"])
    groups = alias_groups(sorted(records), aliases)
    group_best: dict[str, dict] = {}
    for vid, record in records.items():
        record["severity"] = severity_for(severity_rows.get(vid, []))
        record["group"] = groups[vid]["label"]
        best = group_best.get(record["group"])
        if best is None or (record["severity"]["score"] or -1) > (best["score"] or -1):
            group_best[record["group"]] = record["severity"]
    for record in records.values():
        # Records of one issue share a severity: a PYSEC record without a vector inherits the
        # GHSA record's score instead of showing as unrated.
        record["severity"] = group_best[record["group"]]

    events: dict[tuple, list[dict]] = defaultdict(list)
    for row in data["events"]:
        events[(row["vulnerability_id"], row["package_id"])].append(row)

    exposed_pairs: dict[tuple[int, str], set[int]] = defaultdict(set)  # (pkg, vuln) -> release ids
    for row in data["exposure"]:
        hit = row.get("in_range")
        if hit is None:
            hit = row.get("in_enumerated")
        if hit and row["vulnerability_id"] in records and row["package_id"] in by_id:
            exposed_pairs[(row["package_id"], row["vulnerability_id"])].add(row["release_id"])

    # per package ----------------------------------------------------------------------
    package_files: dict[str, dict] = {}
    rows_for_table: list[dict] = []
    group_published: dict[str, str | None] = {}
    group_level: dict[str, str | None] = {}
    group_tiers: dict[str, set[str]] = defaultdict(set)
    group_ids: dict[str, set[str]] = defaultdict(set)
    fix_windows: dict[str, list[dict]] = {"A": [], "B": []}
    latest_ids = latest_release_ids(packages, data["releases"])
    deps_by_release = _dependencies_by_release(data)

    for package in packages:
        pid = package["package_id"]
        name = package["canonical_name"]
        rels = releases_by_pkg.get(pid, [])
        ordered = [(parse_version(r["version"]), r) for r in rels]
        ordered = sorted(((v, r) for v, r in ordered if v is not None), key=lambda item: item[0])
        times = [as_dt(r.get("uploaded_at")) for r in rels if as_dt(r.get("uploaded_at"))]
        first_time = min(times) if times else None
        index_of = {r["release_id"]: i for i, r in enumerate(rels)}

        per_group: dict[str, dict] = {}
        for vid in sorted(pkg_records.get(pid, ())):
            record = records[vid]
            label = record["group"]
            group = per_group.setdefault(label, {
                "id": label, "ids": [], "aliases": set(), "level": None, "score": None,
                "vector": None, "sev_type": None, "published": None, "modified": None,
                "summary": None, "windows": {}, "ranges": {}, "git_ranges": 0, "exposed": set(),
            })
            group["ids"].append(vid)
            group["aliases"].update(groups[vid]["aliases"])
            group["aliases"].update(a for a in groups[vid]["ids"] if a != vid)
            sev = record["severity"]
            better = group["score"] is None or (sev["score"] or 0) > group["score"]
            if sev["score"] is not None and better:
                group.update(level=sev["level"], score=sev["score"], vector=sev["vector"],
                             sev_type=sev["type"])
            elif group["sev_type"] is None and sev["type"]:
                group.update(vector=sev["vector"], sev_type=sev["type"])
            if record["published"] and (not group["published"]
                                        or record["published"] < group["published"]):
                group["published"] = record["published"]
            group["modified"] = max(filter(None, [group["modified"], record["modified"]]),
                                    default=None)
            group["summary"] = group["summary"] or record["summary"]
            evs = events.get((vid, pid), [])
            for window in _windows_from_events(evs):
                resolved = _resolve_window(window, ordered, first_time, as_of)
                group["windows"][(window["from"], window["to"], window["kind"])] = resolved
            seen_ranges = {}
            for event in evs:
                seen_ranges.setdefault((event["entry_index"], event["range_index"]),
                                       {"type": event["range_type"], "events": []})
                seen_ranges[(event["entry_index"], event["range_index"])]["events"].append(
                    [event["event_type"], event["version_string"]])
            for rng in seen_ranges.values():
                if rng["type"] == "GIT":
                    group["git_ranges"] += 1
                else:
                    group["ranges"][json.dumps(rng, sort_keys=True)] = rng
            for release_id in exposed_pairs.get((pid, vid), ()):
                if release_id in index_of:
                    group["exposed"].add(index_of[release_id])

        group_list = []
        for label, group in per_group.items():
            group["aliases"] = sorted(a for a in group["aliases"] if a not in group["ids"]
                                      and a != label)
            group["ids"] = sorted(set(group["ids"]))
            windows = sorted(group["windows"].values(),
                             key=lambda w: (w["start"] or "", w["end"] or ""))
            group["windows"] = [{"from": w["from"], "to": w["to"], "kind": w["kind"],
                                 "start": w["start"], "end": w["end"], "origin": w["origin"],
                                 "days": w["days"]} for w in windows]
            group["ranges"] = list(group["ranges"].values())
            group["fixed_in"] = sorted({w["to"] for w in windows if w["kind"] == "fixed"},
                                       key=lambda v: (parse_version(v) or Version("0"), v))
            group["exposed"] = _runs(sorted(group["exposed"]))
            group["n_exposed"] = sum(b - a + 1 for a, b in group["exposed"])
            group_list.append(group)
            group_published.setdefault(label, group["published"])
            if group["published"] and (group_published[label] is None
                                       or group["published"] < group_published[label]):
                group_published[label] = group["published"]
            group_level[label] = worse(group_level.get(label), group["level"])
            group_tiers[label].add(package.get("seed_tier") or "")
            group_ids[label].update(group["ids"])
            tier = package.get("seed_tier")
            if tier in fix_windows:
                fix_windows[tier].extend(w for w in group["windows"] if w["days"] is not None)
        group_list.sort(key=lambda g: g["published"] or "", reverse=True)

        # per-release exposure summary
        release_items = []
        affected = 0
        for i, row in enumerate(rels):
            hits = [g for g in group_list if any(a <= i <= b for a, b in g["exposed"])]
            top = None
            for g in hits:
                top = worse(top, g["level"] or "u")
            affected += 1 if hits else 0
            release_items.append({
                "v": row["version"], "t": iso(row.get("uploaded_at")),
                "y": 1 if row.get("yanked") else 0,
                "p": 1 if (row.get("is_prerelease") or row.get("is_dev")) else 0,
                "a": len(hits), "s": top,
            })
        top_level = None
        for g in group_list:
            top_level = worse(top_level, g["level"] or "u")
        days = [w["days"] for g in group_list for w in g["windows"] if w["days"] is not None]
        latest_idx = index_of.get(latest_ids.get(pid))
        dep = _package_dependencies(latest_ids.get(pid), rels, deps_by_release, data)
        stats = {
            "releases": len(rels), "advisories": len(group_list),
            "records": sum(len(g["ids"]) for g in group_list),
            "affected_releases": affected,
            "share_affected": round(affected / len(rels), 4) if rels else None,
            "max_level": top_level,
            "median_fix_days": median(days), "fix_windows": len(days),
            "latest_affected": bool(latest_idx is not None
                                    and release_items[latest_idx]["a"] > 0),
            "first_release": iso(first_time), "last_release": iso(max(times)) if times else None,
        }
        package_files[f"packages/{name}.json"] = {
            **meta,
            "package": {
                "name": name, "display": package.get("display_name") or name,
                "tier": package.get("seed_tier"), "summary": trim(package.get("summary"), 300),
                "repo_url": package.get("repo_url"), "license": trim(package.get("license_raw"),
                                                                        120),
                "latest": package.get("latest_version"),
            },
            "stats": stats, "releases": release_items, "advisories": group_list,
            "dependencies": dep,
        }
        rows_for_table.append({
            "n": name, "d": package.get("display_name") or name, "tier": package.get("seed_tier"),
            "s": trim(package.get("summary"), 140), "latest": package.get("latest_version"),
            **{k: stats[k] for k in ("releases", "advisories", "affected_releases",
                                     "share_affected", "max_level", "latest_affected",
                                     "last_release", "median_fix_days")},
        })

    files = dict(package_files)
    files["packages.json"] = {**meta, "packages": rows_for_table}
    files["advisories.json"] = {**meta, "advisories": _advisory_index(records, groups, by_id)}
    files["overview.json"] = _overview(data, meta, package_files, group_published, group_level,
                                       group_tiers, fix_windows, repo_url)
    files["pipeline.json"] = _pipeline(data, meta, is_sample, repo_url)
    return files


def _advisory_index(records: dict, groups: dict, by_id: dict) -> list[dict]:
    items = []
    for vid in sorted(records):
        record = records[vid]
        sev = record["severity"]
        others = [a for a in groups[vid]["aliases"]] + [i for i in groups[vid]["ids"] if i != vid]
        items.append({
            "id": vid, "g": record["group"], "aliases": sorted(set(others)),
            "p": record["published"], "l": sev["level"], "s": sev["score"],
            "pk": sorted(by_id[pid]["canonical_name"] for pid in record["packages"]),
        })
    items.sort(key=lambda item: item["p"] or "", reverse=True)
    return items


def _dependencies_by_release(data: dict) -> dict:
    direct: dict[int, list[dict]] = defaultdict(list)
    for row in data.get("dependencies", []):
        direct[row["release_id"]].append(row)
    resolved: dict[int, list[dict]] = defaultdict(list)
    for row in data.get("resolved", []):
        resolved[row["root_release_id"]].append(row)
    return {"direct": direct, "resolved": resolved}


def _package_dependencies(release_id, rels, deps, data) -> dict:
    version = next((r["version"] for r in rels if r["release_id"] == release_id), None)
    direct = deps["direct"].get(release_id, [])
    resolved = deps["resolved"].get(release_id, [])
    spec_for = {}
    for row in direct:
        if row.get("target_package_name"):
            spec_for.setdefault(row["target_package_name"], row)
    items = []
    if resolved:
        for row in resolved:
            match = spec_for.get(row["dependency_package_name"]) if row["depth"] == 1 else None
            items.append({
                "name": row["dependency_package_name"], "depth": int(row["depth"]),
                "relation": row["relation"], "version": row.get("node_version"),
                "spec": (match or {}).get("specifier") or None,
                "marker": (match or {}).get("marker") or None, "valid": True,
            })
        source = "resolved"
    else:
        for row in direct:
            items.append({
                "name": row.get("target_package_name") or row["raw_requirement"], "depth": 1,
                "relation": "DIRECT", "version": None, "spec": row.get("specifier") or None,
                "marker": row.get("marker") or None, "valid": bool(row["requirement_valid"]),
                "extra_only": bool(row.get("is_extra_only")),
                "conditional": bool(row.get("is_conditional")),
                "raw": row["raw_requirement"] if not row["requirement_valid"] else None,
            })
        source = "direct" if direct else "none"
    items.sort(key=lambda d: (d["depth"], d["name"]))
    return {"release": version, "source": source, "total": len(items),
            "items": items[:MAX_DEPENDENCIES]}


def _overview(data, meta, package_files, group_published, group_level, group_tiers, fix_windows,
              repo_url) -> dict:
    packages = data["packages"]
    tier_a = [f for f in package_files.values() if f["package"]["tier"] == "A"]
    tiers = defaultdict(int)
    for package in packages:
        tiers[package.get("seed_tier") or "-"] += 1
    releases_all = sum(f["stats"]["releases"] for f in package_files.values())
    releases_a = sum(f["stats"]["releases"] for f in tier_a)
    affected_a = sum(f["stats"]["affected_releases"] for f in tier_a)
    a_groups = {label for label, tiers_ in group_tiers.items() if "A" in tiers_}
    seen_records ={vid for pf in tier_a for f in pf["advisories"] for vid in f["ids"]}

    by_year: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for label in a_groups:
        published = group_published.get(label)
        if published:
            by_year[int(published[:4])][group_level.get(label) or "unrated"] += 1
    rel_years: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    for pf in tier_a:
        for release in pf["releases"]:
            if release["t"]:
                year = int(release["t"][:4])
                rel_years[year][0] += 1
                rel_years[year][1] += 1 if release["a"] else 0
    windows = fix_windows["A"]
    days = [w["days"] for w in windows]
    bins = []
    for label, low, high in FIX_BINS:
        bins.append({"label": label, "from": low, "to": None if high == math.inf else high,
                     "count": sum(1 for d in days if low <= d < high)})
    all_a_windows = [w for pf in tier_a for f in pf["advisories"] for w in f["windows"]]
    top = sorted(tier_a, key=lambda f: (-f["stats"]["advisories"], f["package"]["name"]))[:10]
    levels = defaultdict(int)
    for label in a_groups:
        levels[group_level.get(label) or "unrated"] += 1
    return {
        **meta,
        "repo_url": repo_url,
        "tiers": {"A": tiers.get("A", 0), "B": tiers.get("B", 0)},
        "headline": {
            "packages": len(packages), "packages_tier_a": tiers.get("A", 0),
            "packages_tier_b": tiers.get("B", 0),
            "releases": releases_all, "releases_tier_a": releases_a,
            "advisories": len(a_groups), "advisory_records": len(seen_records),
            "affected_releases": affected_a,
            "share_affected": round(affected_a / releases_a, 4) if releases_a else None,
            "median_fix_days": median(days), "fix_windows": len(days),
            "excluded_advisories": data.get("advisories_excluded", 0),
        },
        "severity_mix": dict(levels),
        "advisories_by_year": [
            {"year": year, **{k: by_year[year].get(k, 0) for k in (*LEVELS, "unrated")}}
            for year in sorted(by_year)
        ],
        "affected_by_year": [
            {"year": year, "releases": rel_years[year][0], "affected": rel_years[year][1],
             "share": round(rel_years[year][1] / rel_years[year][0], 4)}
            for year in sorted(rel_years)
        ],
        "time_to_fix": {
            "bins": bins, "median_days": median(days), "n": len(days),
            "excluded": {
                "since_first_release": sum(1 for w in all_a_windows if w["origin"]
                                           and w["kind"] != "open"),
                "still_open": sum(1 for w in all_a_windows if w["kind"] == "open"),
                "fix_date_unknown": sum(1 for w in all_a_windows
                                        if w["kind"] != "open" and w["end"] is None),
            },
        },
        "top_packages": [
            {"name": f["package"]["name"], "advisories": f["stats"]["advisories"],
             "share_affected": f["stats"]["share_affected"],
             "max_level": f["stats"]["max_level"]}
            for f in top if f["stats"]["advisories"] > 0
        ],
    }


def _pipeline(data: dict, meta: dict, is_sample: bool, repo_url: str) -> dict:
    pipe = data.get("pipeline") or {}
    run = data.get("run_latest") or data.get("run") or {}
    started, finished = as_dt(run.get("started_at")), as_dt(run.get("finished_at"))
    run_out = {
        "id": run.get("run_id"), "status": run.get("status") or ("sample" if is_sample else None),
        "started_at": iso(started), "finished_at": iso(finished),
        "duration_s": round((finished - started).total_seconds(), 1) if started and finished
        else None,
        "git_commit": (run.get("git_commit") or "")[:10] or None,
        "config_hash": (run.get("config_hash") or "")[:12] or None,
        "notes": trim(run.get("notes"), 300),
    }
    raw = [{"source": r["source"], "responses": int(r["responses"]), "ok": int(r["ok"]),
            "not_found": int(r["not_found"]), "other_status": int(r["other_status"])}
           for r in pipe.get("raw_by_source", [])]
    counts = [{"stage": r["stage"], "reason": r["reason_code"], "count": int(r["n"])}
              for r in pipe.get("quarantine_counts", [])]
    table_rows = {r["table_name"]: int(r["n"]) for r in pipe.get("table_counts", [])}
    total_raw = sum(r["responses"] for r in raw)
    ok_raw = sum(r["ok"] for r in raw)
    bad_raw = int(pipe.get("quarantine_distinct", 0))
    total_q = sum(c["count"] for c in counts)
    by_stage = defaultdict(int)
    for c in counts:
        by_stage[c["stage"]] += c["count"]
    by_reason: dict[str, int] = {code: 0 for code in REASON_CODES}
    for c in counts:
        by_reason[c["reason"]] = by_reason.get(c["reason"], 0) + c["count"]
    dq = [{"check": r["check_name"], "dimension": r["dimension"], "table": r.get("table_name"),
           "value": num(r["metric_value"]), "threshold": num(r.get("threshold")),
           "passed": bool(r["passed"])} for r in pipe.get("dq_results", [])]
    load_skipped = bool(pipe.get("load_skipped"))
    stages = [
        {"key": "extract", "label": "Extract", "caption": "PyPI JSON, OSV, deps.dev to raw files",
         "status": "ok" if total_raw else "unknown", "metrics": [
             {"label": "responses saved", "value": total_raw},
             {"label": "HTTP 200", "value": ok_raw},
             {"label": "404 / other", "value": sum(r["not_found"] + r["other_status"]
                                                    for r in raw)}]},
        {"key": "validate", "label": "Validate", "caption": "Pydantic contracts per response",
         "status": "warn" if total_q else ("ok" if total_raw else "unknown"), "metrics": [
             {"label": "passed", "value": max(ok_raw - bad_raw, 0)},
             {"label": "quarantined records", "value": by_stage.get("validate", 0)},
             {"label": "responses rejected", "value": bad_raw}]},
        {"key": "transform", "label": "Transform", "caption": "pandas frames in loader shape",
         "status": "ok" if table_rows.get("release") else "unknown", "metrics": [
             {"label": "package rows", "value": table_rows.get("package", 0)},
             {"label": "release rows", "value": table_rows.get("release", 0)},
             {"label": "quarantined here", "value": by_stage.get("transform", 0)}]},
        {"key": "load", "label": "Load", "caption": "PostgreSQL upserts, one transaction",
         "status": "skipped" if load_skipped else (
             "ok" if run_out["status"] == "succeeded" else (
                 "fail" if run_out["status"] == "failed" else "unknown")),
         "metrics": [
             {"label": "release rows",
              "value": None if load_skipped else table_rows.get("release")},
             {"label": "dependency rows",
              "value": None if load_skipped else table_rows.get("dependency")},
             {"label": "vulnerability rows",
              "value": None if load_skipped else table_rows.get("vulnerability")}],
         "note": pipe.get("load_note")},
    ]
    return {
        **meta, "repo_url": repo_url, "run": run_out, "stages": stages, "sources": raw,
        "quarantine": {
            "total": total_q,
            "by_reason": [{"reason": k, "count": v} for k, v in by_reason.items()],
            "by_stage": dict(by_stage),
            "samples": [{"id": r.get("quarantine_id"), "raw_object_id": r.get("raw_object_id"),
                         "stage": r["stage"], "reason": r["reason_code"],
                         "field_path": r.get("field_path"), "message": trim(r.get("message"), 200)}
                        for r in pipe.get("quarantine_samples", [])],
        },
        "quality": {
            "passed": sum(1 for r in dq if r["passed"]), "failed": sum(1 for r in dq
                                                                         if not r["passed"]),
            "results": dq,
        },
        "tables": [{"name": n, "rows": table_rows[n]} for n in TABLES if n in table_rows],
        "recent_runs": [{"id": r["run_id"], "status": r["status"],
                         "started_at": iso(r["started_at"]),
                         "finished_at": iso(r.get("finished_at")),
                         "git_commit": (r.get("git_commit") or "")[:10] or None,
                         "notes": trim(r.get("notes"), 160)} for r in data.get("recent_runs", [])],
        "excluded_advisories": data.get("advisories_excluded", 0),
        "sample_note": pipe.get("sample_note"),
    }


# ------------------------------------------------------------------------------------ writing


def to_json(payload, *, indent: int | None = None) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=indent,
                      separators=(",", ": ") if indent else (",", ":"), default=_default)


def _default(value):
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Decimal):
        return num(value)
    if isinstance(value, datetime):
        return iso(value)
    raise TypeError(f"cannot serialise {type(value).__name__}")


def write_files(files: dict, out_dir: Path) -> list[Path]:
    """Write the JSON files. Old per-package files in out_dir/packages are replaced."""
    out_dir = Path(out_dir)
    package_dir = out_dir / "packages"
    package_dir.mkdir(parents=True, exist_ok=True)
    for stale in package_dir.glob("*.json"):
        stale.unlink()
    written = []
    for relative, payload in sorted(files.items()):
        path = out_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        indent = 2 if relative in ("overview.json", "pipeline.json") else None
        path.write_text(to_json(payload, indent=indent) + "\n", encoding="utf-8")
        written.append(path)
    return written


def site_size(out_dir: Path) -> int:
    return sum(p.stat().st_size for p in Path(out_dir).rglob("*") if p.is_file())


# ----------------------------------------------------------------------------------------- CLI


def load_env_file(path: Path) -> None:
    """Optional: read DATABASE_URL from a local .env without overriding the environment."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    if path.exists():
        load_dotenv(path, override=False)


def main(argv: list[str] | None = None, connect=None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Export dashboard JSON from PostgreSQL.")
    parser.add_argument("--out", type=Path, default=root / "dashboard" / "data")
    parser.add_argument("--as-of", help="ISO timestamp used as 'now' (default: current time)")
    parser.add_argument("--repo-url", default=os.environ.get("R2R_REPO_URL", DEFAULT_REPO_URL))
    args = parser.parse_args(argv)

    load_env_file(root / ".env")
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set. Set it in the environment or in .env.", file=sys.stderr)
        return 2
    as_of = as_dt(args.as_of) if args.as_of else datetime.now(UTC)

    if connect is None:
        import psycopg

        def connect(dsn):
            return psycopg.connect(dsn)

    with connect(url) as conn:
        try:
            conn.read_only = True
        except (AttributeError, TypeError):
            pass
        data = fetch_dataset(conn, as_of)

    files = build_files(data, is_sample=False, repo_url=args.repo_url)
    written = write_files(files, args.out)
    size = site_size(args.out)
    print(f"wrote {len(written)} files to {args.out} ({size / 1024:.0f} KB)")
    if size > 5 * 1024 * 1024:
        print("warning: dashboard/data is over 5 MB; trim packages or releases", file=sys.stderr)
    if not data["packages"]:
        print("warning: no seed packages found; is the database loaded?", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
