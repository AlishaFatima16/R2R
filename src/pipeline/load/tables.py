"""Table definitions for the loader, and the load() entry point.

Frames carry natural keys, never surrogate IDs (see docs/interfaces.md, section 4).
The loader looks up the IDs. Tables are loaded in foreign-key order.
"""

from __future__ import annotations

import pandas as pd

from pipeline.load.loader import LoadError, TableResult, TableSpec, upsert

PACKAGE = TableSpec(
    table="package",
    columns=(
        ("canonical_name", "TEXT"),
        ("display_name", "TEXT"),
        ("in_seed", "BOOLEAN"),
        ("seed_tier", "CHAR(1)"),
        ("summary", "TEXT"),
        ("repo_url", "TEXT"),
        ("license_raw", "TEXT"),
        ("latest_version", "TEXT"),
        ("last_serial", "BIGINT"),
        ("raw_object_id", "BIGINT"),
        ("content_hash", "CHAR(64)"),
    ),
    key=("canonical_name",),
    upsert_sql="""
        INSERT INTO package AS t
            (canonical_name, display_name, in_seed, seed_tier, summary, repo_url,
             license_raw, latest_version, last_serial, raw_object_id, content_hash)
        SELECT canonical_name, display_name, in_seed, seed_tier, summary, repo_url,
               license_raw, latest_version, last_serial, raw_object_id, content_hash
        FROM stg_package
        ON CONFLICT (canonical_name) DO UPDATE SET
            display_name   = EXCLUDED.display_name,
            in_seed        = EXCLUDED.in_seed,
            seed_tier      = EXCLUDED.seed_tier,
            summary        = EXCLUDED.summary,
            repo_url       = EXCLUDED.repo_url,
            license_raw    = EXCLUDED.license_raw,
            latest_version = EXCLUDED.latest_version,
            last_serial    = EXCLUDED.last_serial,
            raw_object_id  = EXCLUDED.raw_object_id,
            content_hash   = EXCLUDED.content_hash
        WHERE t.content_hash IS DISTINCT FROM EXCLUDED.content_hash
        RETURNING (xmax = 0) AS inserted
    """,
)

RELEASE = TableSpec(
    table="release",
    columns=(
        ("canonical_name", "TEXT"),
        ("version", "TEXT"),
        ("version_valid", "BOOLEAN"),
        ("version_rank", "INT"),
        ("is_prerelease", "BOOLEAN"),
        ("is_dev", "BOOLEAN"),
        ("uploaded_at", "TIMESTAMPTZ"),
        ("yanked", "BOOLEAN"),
        ("yanked_reason", "TEXT"),
        ("requires_python", "TEXT"),
        ("deps_fetched", "BOOLEAN"),
        ("raw_object_id", "BIGINT"),
        ("content_hash", "CHAR(64)"),
    ),
    key=("canonical_name", "version"),
    unresolved_sql="""
        SELECT DISTINCT s.canonical_name
        FROM stg_release s
        LEFT JOIN package p ON p.canonical_name = s.canonical_name
        WHERE p.package_id IS NULL
        ORDER BY 1
        LIMIT 10
    """,
    upsert_sql="""
        INSERT INTO release AS t
            (package_id, version, version_valid, version_rank, is_prerelease, is_dev,
             uploaded_at, yanked, yanked_reason, requires_python, deps_fetched,
             raw_object_id, content_hash)
        SELECT p.package_id, s.version, s.version_valid, s.version_rank, s.is_prerelease,
               s.is_dev, s.uploaded_at, s.yanked, s.yanked_reason, s.requires_python,
               s.deps_fetched, s.raw_object_id, s.content_hash
        FROM stg_release s
        JOIN package p ON p.canonical_name = s.canonical_name
        ON CONFLICT (package_id, version) DO UPDATE SET
            version_valid   = EXCLUDED.version_valid,
            version_rank    = EXCLUDED.version_rank,
            is_prerelease   = EXCLUDED.is_prerelease,
            is_dev          = EXCLUDED.is_dev,
            uploaded_at     = EXCLUDED.uploaded_at,
            yanked          = EXCLUDED.yanked,
            yanked_reason   = EXCLUDED.yanked_reason,
            requires_python = EXCLUDED.requires_python,
            deps_fetched    = EXCLUDED.deps_fetched,
            raw_object_id   = EXCLUDED.raw_object_id,
            content_hash    = EXCLUDED.content_hash
        WHERE t.content_hash IS DISTINCT FROM EXCLUDED.content_hash
        RETURNING (xmax = 0) AS inserted
    """,
)

# Append-only tables: every row is inserted. Frames do not carry run_id; load() adds it.
QUARANTINE = TableSpec(
    table="quarantine",
    columns=(
        ("run_id", "BIGINT"),
        ("raw_object_id", "BIGINT"),
        ("stage", "TEXT"),
        ("reason_code", "TEXT"),
        ("field_path", "TEXT"),
        ("message", "TEXT"),
    ),
    key=(),
    needs_run_id=True,
    upsert_sql="""
        INSERT INTO quarantine
            (run_id, raw_object_id, stage, reason_code, field_path, message)
        SELECT run_id, raw_object_id, stage, reason_code, field_path, message
        FROM stg_quarantine
        RETURNING true AS inserted
    """,
)

DATA_QUALITY_RESULT = TableSpec(
    table="data_quality_result",
    columns=(
        ("run_id", "BIGINT"),
        ("check_name", "TEXT"),
        ("dimension", "TEXT"),
        ("table_name", "TEXT"),
        ("metric_value", "NUMERIC"),
        ("threshold", "NUMERIC"),
        ("passed", "BOOLEAN"),
        ("details", "JSONB"),
    ),
    key=(),
    needs_run_id=True,
    upsert_sql="""
        INSERT INTO data_quality_result
            (run_id, check_name, dimension, table_name, metric_value, threshold,
             passed, details)
        SELECT run_id, check_name, dimension, table_name, metric_value, threshold,
               passed, details
        FROM stg_data_quality_result
        RETURNING true AS inserted
    """,
)

# Foreign-key order. New tables are added here as they are implemented.
LOAD_ORDER: tuple[TableSpec, ...] = (PACKAGE, RELEASE, QUARANTINE, DATA_QUALITY_RESULT)


def load(
    frames: dict[str, pd.DataFrame], conn, run_id: int | None = None
) -> dict[str, TableResult]:
    """Load all given frames in one transaction. Either everything commits or nothing does.

    run_id is required when frames include quarantine or data_quality_result.
    Load quarantine rows in their own load() call, so that they are kept even if the load
    of the data tables fails and rolls back.
    """
    supported = {spec.table for spec in LOAD_ORDER}
    unsupported = sorted(set(frames) - supported)
    if unsupported:
        raise LoadError(f"No loader yet for table(s): {unsupported}")

    results: dict[str, TableResult] = {}
    with conn.transaction():
        for spec in LOAD_ORDER:
            if spec.table in frames:
                results[spec.table] = upsert(conn, spec, frames[spec.table], run_id)
    return results