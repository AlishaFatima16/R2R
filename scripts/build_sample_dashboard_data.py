"""Build the dashboard's sample data from fixtures/. No database and no network.

    python scripts/build_sample_dashboard_data.py
    python scripts/build_sample_dashboard_data.py --out dashboard/data

It runs the repository's own stages on the saved API responses in fixtures/ (validate with the
Pydantic contracts, transform with pandas), reshapes the frames into the rows the SQL views
would return, and hands them to the same code the real export uses. The result is marked
is_sample=true, so the dashboard shows a "sample data" banner until
scripts/export_dashboard_data.py replaces it with a real export.

The seven files in fixtures/bad/ are passed through the validators too, so the Pipeline page
shows real quarantine rows. Nothing is invented: counts come from running the code.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
from export_dashboard_data import (
    DEFAULT_REPO_URL,
    as_dt,
    build_files,
    write_files,
)

from pipeline.orchestrate import (
    OsvPageItem,
    ProjectItem,
    ValidatedBatch,
    VersionItem,
    read_seed_file,
)
from pipeline.quality.rules import run_quality_checks
from pipeline.transform import transform
from pipeline.validate.osv import validate_osv_page
from pipeline.validate.pypi import validate_pypi_project, validate_pypi_version


def records(frame: pd.DataFrame | None) -> list[dict]:
    """DataFrame -> list of dicts with NaN/NaT as None and Timestamps as datetimes."""
    if frame is None or frame.empty:
        return []
    cleaned = frame.astype(object).where(frame.notna(), None)
    rows = cleaned.to_dict("records")
    for row in rows:
        for key, value in row.items():
            if isinstance(value, pd.Timestamp):
                row[key] = value.to_pydatetime()
    return rows


def git_head() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                             check=True, timeout=10, cwd=ROOT)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def load_fixtures(fixtures: Path, seed: dict[str, str]):
    """Validate the real fixtures. Returns the batch plus counts for the pipeline page."""
    projects, pages, versions = [], [], []
    for index, path in enumerate(sorted((fixtures / "pypi_json").glob("*.json")), start=1):
        if path.stem not in seed:
            print(f"skip {path.stem}: not in config/seed.txt")
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        result = validate_pypi_project(body, index)
        if result.value is None:
            raise SystemExit(f"{path.name} failed validation: {result.quarantine[:1]}")
        projects.append(ProjectItem(path.stem, index, result.value))
        # The project response is the latest release's metadata, so it also gives the
        # latest release's dependencies. Older releases need their own per-release responses.
        latest = validate_pypi_version(
            {"info": body["info"], "urls": body.get("urls", []),
             "last_serial": body.get("last_serial")}, index)
        if latest.value is not None:
            versions.append(VersionItem(path.stem, latest.value.info.version, index,
                                        latest.value))
    for index, path in enumerate(sorted((fixtures / "osv").glob("*.json")), start=100):
        if path.stem not in seed:
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        result = validate_osv_page(body, index)
        if result.quarantine:
            raise SystemExit(f"{path.name} has quarantined advisories: {result.quarantine[:1]}")
        pages.append(OsvPageItem(path.stem, index, result.vulns))
    batch = ValidatedBatch(
        run_id=0, seed={p.name: seed[p.name] for p in projects},
        projects=projects, versions=versions, osv_pages=pages)
    return batch, len(projects), len(pages)


def validate_bad(fixtures: Path) -> tuple[list[dict], int, int, int]:
    """Run fixtures/bad/ through the validators. Returns rows, files, pypi-shaped, osv-shaped."""
    rows, pypi_files, osv_files = [], 0, 0
    for index, path in enumerate(sorted((fixtures / "bad").glob("*.json")), start=900):
        body = json.loads(path.read_text(encoding="utf-8"))
        if path.stem == "malformed_identifier":
            osv_files += 1
            found = validate_osv_page({"vulns": [body]}, index).quarantine
        else:
            pypi_files += 1
            found = validate_pypi_project(body, index).quarantine
        for position, row in enumerate(found, start=1):
            rows.append({**row, "quarantine_id": index * 10 + position,
                         "message": f"[{path.stem}] {row['message']}"})
    return rows, pypi_files + osv_files, pypi_files, osv_files


def build_dataset(frames: dict, seed: dict[str, str], as_of: datetime) -> dict:
    """Frames -> the rows that the export queries return (same column names)."""
    pkg_rows = [r for r in records(frames["package"]) if r["in_seed"]]
    pid = {r["canonical_name"]: i for i, r in enumerate(pkg_rows, start=1)}
    packages = [{
        "package_id": pid[r["canonical_name"]], "canonical_name": r["canonical_name"],
        "display_name": r["display_name"], "seed_tier": r["seed_tier"], "summary": r["summary"],
        "repo_url": r["repo_url"], "license_raw": r["license_raw"],
        "latest_version": r["latest_version"], "last_serial": r["last_serial"],
    } for r in pkg_rows]

    releases, release_id = [], {}
    for row in records(frames["release"]):
        if row["canonical_name"] not in pid:
            continue
        release_id[(row["canonical_name"], row["version"])] = len(release_id) + 1
        releases.append({
            "package_id": pid[row["canonical_name"]],
            "release_id": release_id[(row["canonical_name"], row["version"])],
            "version": row["version"], "version_valid": row["version_valid"],
            "version_rank": row["version_rank"], "is_prerelease": row["is_prerelease"],
            "is_dev": row["is_dev"], "uploaded_at": row["uploaded_at"], "yanked": row["yanked"],
            "requires_python": row["requires_python"], "deps_fetched": row["deps_fetched"],
        })

    vulns = {r["vulnerability_id"]: r for r in records(frames["vulnerability"])}
    advisories, in_force, mapped = [], set(), set()
    for row in records(frames["affected_package"]):
        if row["package_name"] not in pid:
            continue
        vuln = vulns[row["vulnerability_id"]]
        mapped.add(row["vulnerability_id"])
        published, withdrawn = as_dt(vuln["published_at"]), as_dt(vuln["withdrawn_at"])
        # Same rule as vulnerabilities_as_of(): published by now and not withdrawn yet.
        if published is None or published > as_of or (withdrawn and withdrawn <= as_of):
            continue
        in_force.add(row["vulnerability_id"])
        advisories.append({
            "package_id": pid[row["package_name"]], "package_name": row["package_name"],
            "entry_index": row["entry_index"], "vulnerability_id": row["vulnerability_id"],
            "published_at": vuln["published_at"], "modified_at": vuln["modified_at"],
            "withdrawn_at": vuln["withdrawn_at"], "summary": vuln["summary"],
            "dates_out_of_order": vuln["dates_out_of_order"],
        })

    entry_pkg = {(r["vulnerability_id"], r["entry_index"]): pid[r["package_name"]]
                 for r in records(frames["affected_package"]) if r["package_name"] in pid}
    range_type = {(r["vulnerability_id"], r["entry_index"], r["range_index"]): r["range_type"]
                  for r in records(frames["affected_range"])}
    events = []
    for row in records(frames["affected_event"]):
        key = (row["vulnerability_id"], row["entry_index"])
        if key not in entry_pkg:
            continue
        events.append({
            "vulnerability_id": row["vulnerability_id"], "package_id": entry_pkg[key],
            "entry_index": row["entry_index"], "range_index": row["range_index"],
            "range_type": range_type[(*key, row["range_index"])],
            "event_order": row["event_order"], "event_type": row["event_type"],
            "version_string": row["version_string"],
        })

    exposure = []
    for row in records(frames["affected_release"]):
        rid = release_id.get((row["canonical_name"], row["version"]))
        if rid is None:
            continue
        exposure.append({
            "release_id": rid, "package_id": pid[row["canonical_name"]],
            "vulnerability_id": row["vulnerability_id"], "in_range": row["in_range"],
            "in_enumerated": row["in_enumerated"],
        })

    latest = {p["canonical_name"]: p["latest_version"] for p in packages}
    dependencies = []
    for row in records(frames["dependency"]):
        if latest.get(row["canonical_name"]) != row["version"]:
            continue
        rid = release_id.get((row["canonical_name"], row["version"]))
        if rid is None:
            continue
        dependencies.append({
            "release_id": rid, "package_id": pid[row["canonical_name"]],
            "target_package_name": row["target_name"], "raw_requirement": row["raw_requirement"],
            "requirement_valid": row["requirement_valid"], "specifier": row["specifier"],
            "marker": row["marker"], "extras": row["extras"],
            "is_extra_only": row["is_extra_only"], "is_conditional": row["is_conditional"],
        })

    return {
        "as_of": as_of, "packages": packages, "releases": releases, "advisories": advisories,
        "advisories_excluded": len(mapped - in_force),
        "aliases": records(frames["vulnerability_alias"]),
        "severities": records(frames["vulnerability_severity"]),
        "events": events, "exposure": exposure, "dependencies": dependencies, "resolved": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dashboard" / "data")
    parser.add_argument("--fixtures", type=Path, default=ROOT / "fixtures")
    parser.add_argument("--seed-file", type=Path, default=ROOT / "config" / "seed.txt")
    args = parser.parse_args(argv)

    as_of = datetime.now(UTC)
    seed = read_seed_file(args.seed_file)
    batch, n_projects, n_pages = load_fixtures(args.fixtures, seed)
    result = transform(batch)
    frames = result.frames
    bad_rows, n_bad, bad_pypi, bad_osv = validate_bad(args.fixtures)
    caught = {row["message"].split("]")[0][1:] for row in bad_rows}
    missed = sorted(p.stem for p in (args.fixtures / "bad").glob("*.json") if p.stem not in caught)
    rejected_note = f"{n_bad - len(missed)} of {n_bad} are rejected by the current validators" + (
        f"; {', '.join(missed)} pass." if missed else ".")

    data = build_dataset(frames, seed, as_of)
    quality = run_quality_checks(frames)
    reasons: dict[tuple[str, str], int] = {}
    for row in bad_rows:
        key = (row["stage"], row["reason_code"])
        reasons[key] = reasons.get(key, 0) + 1
    data["run"] = None
    data["run_latest"] = {
        "run_id": None, "status": "sample", "started_at": as_of, "finished_at": None,
        "git_commit": git_head(), "config_hash": None,
        "notes": "sample built from fixtures/ (no database run)",
    }
    data["recent_runs"] = []
    data["pipeline"] = {
        "raw_by_source": [
            {"source": "pypi_json", "responses": n_projects + bad_pypi, "ok": n_projects + bad_pypi,
             "not_found": 0, "other_status": 0},
            {"source": "osv", "responses": n_pages + bad_osv, "ok": n_pages + bad_osv,
             "not_found": 0, "other_status": 0},
        ],
        "quarantine_counts": [{"stage": s, "reason_code": r, "n": n}
                              for (s, r), n in sorted(reasons.items(), key=lambda i: -i[1])],
        "quarantine_distinct": len({row["raw_object_id"] for row in bad_rows}),
        "quarantine_samples": bad_rows[:25],
        "dq_results": [{"check_name": q.check_name, "dimension": q.dimension,
                        "table_name": q.table_name, "metric_value": q.metric_value,
                        "threshold": q.threshold, "passed": q.passed} for q in quality],
        "table_counts": [{"table_name": name, "n": len(frame)} for name, frame in frames.items()
                         if name in ("package", "release", "dependency", "vulnerability",
                                     "vulnerability_alias", "affected_package",
                                     "affected_release")],
        "load_skipped": True,
        "load_note": "Sample mode: nothing was loaded into PostgreSQL. Row counts are the "
                     "transform output (frames).",
        "sample_note": f"Built by scripts/build_sample_dashboard_data.py from {n_projects} PyPI "
                       f"and {n_pages} OSV fixtures plus {n_bad} deliberately invalid files in "
                       f"fixtures/bad/. {rejected_note} A real run replaces this page.",
    }
    files = build_files(data, is_sample=True, repo_url=DEFAULT_REPO_URL)
    written = write_files(files, args.out)
    print(f"wrote {len(written)} files to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
