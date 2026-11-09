
"""The one-command run: fetch -> save raw -> register -> validate -> transform -> load.

    python -m pipeline.orchestrate --seed-file config/seed.txt
    python -m pipeline.orchestrate --packages six:A flask:A
    python -m pipeline.orchestrate --seed-file config/seed.txt --skip-fetch --run-label run-12

The transform is a plug-in: a function that takes a ValidatedBatch and returns a
TransformResult.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

from pipeline.extract import depsdev as depsdev_adapter
from pipeline.extract import osv as osv_adapter
from pipeline.extract import pypi_json
from pipeline.extract.http import HttpClient
from pipeline.extract.names import canonical_name
from pipeline.extract.raw_writer import body_sha256, read_lines
from pipeline.extract.records import RawRecord
from pipeline.extract.run import DEFAULT_RELEASE_LIMIT, extract_packages
from pipeline.validate.depsdev import validate_depsdev
from pipeline.validate.errors import quarantine_row
from pipeline.validate.osv import OsvVuln, validate_osv_page
from pipeline.validate.pypi import (
    PypiProject,
    PypiVersion,
    validate_pypi_project,
    validate_pypi_version,
)

QUARANTINE_FRAME_COLUMNS = [
    "raw_object_id",
    "stage",
    "reason_code",
    "field_path",
    "message",
]
VALID_TIERS = ("A", "B")


# ---------------------------------------------------------------- what the transform gets


@dataclass(frozen=True)
class ProjectItem:
    name: str
    raw_object_id: int
    project: PypiProject


@dataclass(frozen=True)
class VersionItem:
    name: str
    version: str
    raw_object_id: int
    release: PypiVersion


@dataclass(frozen=True)
class OsvPageItem:
    name: str
    raw_object_id: int
    vulns: list[OsvVuln]


@dataclass(frozen=True)
class DepsDevItem:
    name: str
    version: str
    raw_object_id: int
    graph: object


@dataclass
class ValidatedBatch:
    """Everything that passed validation in one run, plus the seed list."""

    run_id: int
    seed: dict[str, str]
    projects: list[ProjectItem] = field(default_factory=list)
    versions: list[VersionItem] = field(default_factory=list)
    osv_pages: list[OsvPageItem] = field(default_factory=list)
    depsdev_graphs: list[DepsDevItem] = field(default_factory=list)


@dataclass
class TransformResult:
    frames: dict[str, pd.DataFrame] = field(default_factory=dict)
    quarantine: list[dict] = field(default_factory=list)


Transform = Callable[[ValidatedBatch], TransformResult]


def no_transform(batch: ValidatedBatch) -> TransformResult:
    """Placeholder transform that loads nothing."""
    return TransformResult()


# ------------------------------------------------------------------- reading raw files


def scan_raw(root: Path, run_label: str) -> list[RawRecord]:
    """Rebuild a RawRecord for every line in this run's raw files."""
    records = []

    for path in sorted(Path(root).glob(f"data/raw/*/{run_label}/*.jsonl.gz")):
        relative = path.relative_to(root).as_posix()

        for number, line in enumerate(read_lines(root, relative), start=1):
            records.append(
                RawRecord(
                    source=line["source"],
                    request_url=line["request_url"],
                    request_params=line.get("request_params"),
                    http_status=line["http_status"],
                    fetched_at=datetime.fromisoformat(line["fetched_at"]),
                    sha256=body_sha256(line.get("body")),
                    file_path=relative,
                    line_number=number,
                )
            )

    return records


def split_file_name(file_path: str) -> tuple[str, str | None]:
    """Split a raw filename into package name and optional version."""
    stem = Path(file_path).name.removesuffix(".jsonl.gz")
    name, _, version = stem.partition("@")
    return name, (unquote(version) if version else None)


def read_body(
    root: Path,
    record: RawRecord,
    cache: dict[str, list[dict]] | None = None,
):
    """Read the saved response body, optionally caching each file."""
    if cache is None:
        cache = {}

    if record.file_path not in cache:
        cache[record.file_path] = read_lines(root, record.file_path)

    lines = cache[record.file_path]

    if record.line_number > len(lines):
        raise LookupError(
            f"{record.file_path} has no line {record.line_number}"
        )

    return lines[record.line_number - 1]["body"]


@dataclass
class BatchStats:
    lines: int = 0
    not_found: int = 0
    other_status: int = 0
    quarantined: int = 0


def build_batch(
    root: Path,
    records: list[RawRecord],
    raw_ids: dict[tuple[str, int], int],
    run_id: int,
    seed: dict[str, str],
) -> tuple[ValidatedBatch, list[dict], BatchStats]:
    """Validate saved responses and build a batch for transformation."""
    batch = ValidatedBatch(run_id=run_id, seed=seed)
    quarantine: list[dict] = []
    stats = BatchStats()
    cache: dict[str, list[dict]] = {}

    for record in records:
        stats.lines += 1

        if record.http_status == 404:
            stats.not_found += 1
            continue

        if record.http_status != 200:
            stats.other_status += 1
            continue

        raw_id = raw_ids[(record.file_path, record.line_number)]
        name, version = split_file_name(record.file_path)
        body = read_body(root, record, cache)

        if record.source == pypi_json.SOURCE and version is None:
            result = validate_pypi_project(body, raw_id)

            if result.value is not None:
                batch.projects.append(
                    ProjectItem(name, raw_id, result.value)
                )

            quarantine += result.quarantine

        elif record.source == pypi_json.SOURCE:
            result = validate_pypi_version(body, raw_id)

            if result.value is not None:
                batch.versions.append(
                    VersionItem(name, version, raw_id, result.value)
                )

            quarantine += result.quarantine

        elif record.source == osv_adapter.SOURCE:
            page = validate_osv_page(body, raw_id)
            batch.osv_pages.append(
                OsvPageItem(name, raw_id, page.vulns)
            )
            quarantine += page.quarantine

        elif record.source == depsdev_adapter.SOURCE:
            result = validate_depsdev(body, raw_id)

            if result.graph is not None and version is not None:
                batch.depsdev_graphs.append(
                    DepsDevItem(name, version, raw_id, result.graph)
                )

            elif result.graph is not None:
                quarantine.append(
                    quarantine_row(
                        raw_id,
                        "invalid_value",
                        "",
                        "deps.dev record has no package version in its filename.",
                    )
                )

            quarantine += result.quarantine

    stats.quarantined = len(quarantine)

    return batch, quarantine, stats


# ------------------------------------------------------------------------ seed and config


def parse_seed(entries: list[str]) -> dict[str, str]:
    """Parse seed entries such as ['requests,A', 'flask:B']."""
    seed = {}

    for entry in entries:
        text = entry.split("#", 1)[0].strip()

        if not text:
            continue

        name, sep, tier = text.replace(":", ",").partition(",")
        tier = tier.strip().upper()

        if not sep or tier not in VALID_TIERS:
            raise ValueError(
                f"seed entry {entry!r} needs a tier: name,A (A or B)"
            )

        seed[canonical_name(name.strip())] = tier

    return seed


def read_seed_file(path: Path) -> dict[str, str]:
    return parse_seed(Path(path).read_text(encoding="utf-8").splitlines())


def config_hash(
    seed: dict[str, str],
    release_limit: int | None,
    sources: list[str],
) -> str:
    text = json.dumps(
        {
            "seed": sorted(seed.items()),
            "release_limit": release_limit,
            "sources": sorted(sources),
        },
        sort_keys=True,
    )

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return out.stdout.strip() or "unknown"

    except (OSError, subprocess.SubprocessError):
        return "unknown"


# ---------------------------------------------------------------------------- the run


@dataclass
class Ops:
    """Database operations used by a pipeline run."""

    start_run: Callable
    finish_run: Callable
    register_raw_object: Callable
    load: Callable


def default_ops() -> Ops:
    from pipeline.load import runs
    from pipeline.load.tables import load

    return Ops(
        runs.start_run,
        runs.finish_run,
        runs.register_raw_object,
        load,
    )


@dataclass
class RunSummary:
    run_id: int
    run_label: str
    raw_lines: int = 0
    raw_registered_new: int = 0
    stats: BatchStats = field(default_factory=BatchStats)
    fetch_failures: dict[str, str] = field(default_factory=dict)
    load_results: dict = field(default_factory=dict)
    transform_connected: bool = True


def run_pipeline(
    conn,
    seed: dict[str, str],
    root: Path,
    run_label: str | None = None,
    transform: Transform = no_transform,
    client: HttpClient | None = None,
    release_limit: int | None = DEFAULT_RELEASE_LIMIT,
    fetch: bool = True,
    ops: Ops | None = None,
    log=print,
) -> RunSummary:
    """Run the complete pipeline once."""
    ops = ops or default_ops()

    sources = [
        pypi_json.SOURCE,
        osv_adapter.SOURCE,
        depsdev_adapter.SOURCE,
    ]

    run_id = ops.start_run(
        conn,
        git_commit(),
        config_hash(seed, release_limit, sources),
        notes=run_label,
    )

    label = run_label or f"run-{run_id}"

    summary = RunSummary(
        run_id,
        label,
        transform_connected=transform is not no_transform,
    )

    try:
        if fetch:
            extracted = extract_packages(
                list(seed),
                client or HttpClient(),
                root,
                label,
                sources=tuple(sources),
                release_limit=release_limit,
                log=log,
            )

            summary.fetch_failures = extracted.failed

        records = scan_raw(root, label)
        summary.raw_lines = len(records)

        raw_ids: dict[tuple[str, int], int] = {}

        for record in records:
            raw_id, created = ops.register_raw_object(
                conn,
                run_id,
                **record.as_kwargs(),
            )

            raw_ids[(record.file_path, record.line_number)] = raw_id
            summary.raw_registered_new += int(created)

        batch, quarantine, summary.stats = build_batch(
            root,
            records,
            raw_ids,
            run_id,
            seed,
        )

        # Load validation quarantine separately so it survives a failed data load.
        if quarantine:
            frame = pd.DataFrame(
                quarantine,
                columns=QUARANTINE_FRAME_COLUMNS,
            )
            summary.load_results.update(
                ops.load({"quarantine": frame}, conn, run_id)
            )

        result = transform(batch)

        if result.quarantine:
            frame = pd.DataFrame(
                result.quarantine,
                columns=QUARANTINE_FRAME_COLUMNS,
            )
            summary.load_results.update(
                ops.load({"quarantine": frame}, conn, run_id)
            )

        if result.frames:
            summary.load_results.update(
                ops.load(result.frames, conn, run_id)
            )

        ops.finish_run(conn, run_id, "succeeded", notes=_notes(summary))

    except Exception as error:
        ops.finish_run(
            conn,
            run_id,
            "failed",
            notes=f"{type(error).__name__}: {error}"[:500],
        )
        raise

    return summary


def _notes(summary: RunSummary) -> str:
    return (
        f"{summary.run_label}: {summary.raw_lines} raw lines, "
        f"{summary.stats.quarantined} quarantined, "
        f"{len(summary.fetch_failures)} fetch failures"
    )


# -------------------------------------------------------------------------------- CLI


def print_summary(summary: RunSummary, log=print) -> None:
    log(f"run {summary.run_id} ({summary.run_label})")
    log(
        f"  raw lines: {summary.raw_lines} "
        f"({summary.raw_registered_new} newly registered)"
    )
    log(
        f"  404s: {summary.stats.not_found}, "
        f"other statuses: {summary.stats.other_status}"
    )
    log(f"  quarantined records: {summary.stats.quarantined}")
    log(f"  fetch failures: {len(summary.fetch_failures)}")

    for table, result in summary.load_results.items():
        log(
            f"  {table}: {result.inserted} inserted, "
            f"{result.updated} updated, {result.unchanged} unchanged"
        )

    if not summary.transform_connected:
        log(
            "  NOTE: the transform is not connected yet, "
            "so only quarantine rows were loaded."
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the whole R2R pipeline once."
    )

    parser.add_argument(
        "--seed-file",
        type=Path,
        help="lines of: name,tier (tier A or B)",
    )
    parser.add_argument(
        "--packages",
        nargs="*",
        default=[],
        help="name:tier, for quick tests",
    )
    parser.add_argument(
        "--run-label",
        help="reuse a label to resume or replay its raw files",
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="only replay saved raw files",
    )
    parser.add_argument(
        "--release-limit",
        type=int,
        default=DEFAULT_RELEASE_LIMIT,
    )
    parser.add_argument("--root", type=Path, default=Path("."))

    args = parser.parse_args(argv)

    seed = {}

    if args.seed_file:
        seed.update(read_seed_file(args.seed_file))

    seed.update(parse_seed(args.packages))

    if not seed:
        parser.error("give --seed-file or --packages")

    if args.skip_fetch and not args.run_label:
        parser.error("--skip-fetch needs --run-label (which run's raw files to replay)")

    import psycopg
    from dotenv import load_dotenv

    load_dotenv()

    url = os.environ.get("DATABASE_URL")

    if not url:
        parser.error("DATABASE_URL is not set (see .env.example)")

    transform = _connected_transform()

    with psycopg.connect(url, autocommit=True) as conn:
        summary = run_pipeline(
            conn,
            seed,
            args.root,
            args.run_label,
            transform=transform,
            release_limit=args.release_limit,
            fetch=not args.skip_fetch,
        )

    print_summary(summary)

    return 1 if summary.fetch_failures else 0


def _connected_transform() -> Transform:
    """Load the real transform plug-in if it exists."""
    if importlib.util.find_spec("pipeline.transform") is None:
        return no_transform

    module = importlib.import_module("pipeline.transform")

    if not hasattr(module, "transform"):
        raise SystemExit(
            "pipeline.transform exists but defines no transform(batch) function"
        )

    return module.transform


if __name__ == "__main__":
    raise SystemExit(main())
