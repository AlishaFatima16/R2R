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

DEPENDENCY = TableSpec(
    table="dependency",
    columns=(
        ("canonical_name", "TEXT"),
        ("version", "TEXT"),
        ("raw_requirement", "TEXT"),
        ("requirement_valid", "BOOLEAN"),
        ("target_name", "TEXT"),
        ("extras", "TEXT[]"),
        ("specifier", "TEXT"),
        ("marker", "TEXT"),
        ("is_extra_only", "BOOLEAN"),
        ("is_conditional", "BOOLEAN"),
    ),
    key=("canonical_name", "version", "raw_requirement"),
    unresolved_sql="""
        SELECT DISTINCT 'release ' || s.canonical_name || '==' || s.version AS problem
        FROM stg_dependency s
        LEFT JOIN package p ON p.canonical_name = s.canonical_name
        LEFT JOIN release r ON r.package_id = p.package_id AND r.version = s.version
        WHERE r.release_id IS NULL
        UNION
        SELECT DISTINCT 'target package ' || s.target_name
        FROM stg_dependency s
        LEFT JOIN package tp ON tp.canonical_name = s.target_name
        WHERE s.target_name IS NOT NULL AND tp.package_id IS NULL
        UNION
        SELECT DISTINCT 'valid requirement without target_name: ' || s.raw_requirement
        FROM stg_dependency s
        WHERE s.requirement_valid AND s.target_name IS NULL
        ORDER BY 1
        LIMIT 10
    """,
    upsert_sql="""
        INSERT INTO dependency AS t
            (release_id, raw_requirement, requirement_valid, target_package_id, extras,
             specifier, marker, is_extra_only, is_conditional)
        SELECT r.release_id, s.raw_requirement, s.requirement_valid, tp.package_id,
               s.extras, s.specifier, s.marker, s.is_extra_only, s.is_conditional
        FROM stg_dependency s
        JOIN package p ON p.canonical_name = s.canonical_name
        JOIN release r ON r.package_id = p.package_id AND r.version = s.version
        LEFT JOIN package tp ON tp.canonical_name = s.target_name
        ON CONFLICT (release_id, raw_requirement) DO UPDATE SET
            requirement_valid = EXCLUDED.requirement_valid,
            target_package_id = EXCLUDED.target_package_id,
            extras            = EXCLUDED.extras,
            specifier         = EXCLUDED.specifier,
            marker            = EXCLUDED.marker,
            is_extra_only     = EXCLUDED.is_extra_only,
            is_conditional    = EXCLUDED.is_conditional
        WHERE (t.requirement_valid, t.target_package_id, t.extras, t.specifier, t.marker,
               t.is_extra_only, t.is_conditional)
              IS DISTINCT FROM
              (EXCLUDED.requirement_valid, EXCLUDED.target_package_id, EXCLUDED.extras,
               EXCLUDED.specifier, EXCLUDED.marker, EXCLUDED.is_extra_only,
               EXCLUDED.is_conditional)
        RETURNING (xmax = 0) AS inserted
    """,
)

VULNERABILITY = TableSpec(
    table="vulnerability",
    columns=(
        ("vulnerability_id", "TEXT"),
        ("published_at", "TIMESTAMPTZ"),
        ("modified_at", "TIMESTAMPTZ"),
        ("withdrawn_at", "TIMESTAMPTZ"),
        ("summary", "TEXT"),
        ("details", "TEXT"),
        ("schema_version", "TEXT"),
        ("dates_out_of_order", "BOOLEAN"),
        ("raw_object_id", "BIGINT"),
        ("content_hash", "CHAR(64)"),
    ),
    key=("vulnerability_id",),
    upsert_sql="""
        INSERT INTO vulnerability AS t
            (vulnerability_id, published_at, modified_at, withdrawn_at, summary, details,
             schema_version, dates_out_of_order, raw_object_id, content_hash)
        SELECT vulnerability_id, published_at, modified_at, withdrawn_at, summary, details,
               schema_version, dates_out_of_order, raw_object_id, content_hash
        FROM stg_vulnerability
        ON CONFLICT (vulnerability_id) DO UPDATE SET
            published_at       = EXCLUDED.published_at,
            modified_at        = EXCLUDED.modified_at,
            withdrawn_at       = EXCLUDED.withdrawn_at,
            summary            = EXCLUDED.summary,
            details            = EXCLUDED.details,
            schema_version     = EXCLUDED.schema_version,
            dates_out_of_order = EXCLUDED.dates_out_of_order,
            raw_object_id      = EXCLUDED.raw_object_id,
            content_hash       = EXCLUDED.content_hash
        WHERE t.content_hash IS DISTINCT FROM EXCLUDED.content_hash
        RETURNING (xmax = 0) AS inserted
    """,
)

# Aliases are insert-only: a row that already exists is left alone. An alias that an
# advisory later drops is not deleted here.
VULNERABILITY_ALIAS = TableSpec(
    table="vulnerability_alias",
    columns=(
        ("vulnerability_id", "TEXT"),
        ("alias", "TEXT"),
    ),
    key=("vulnerability_id", "alias"),
    unresolved_sql="""
        SELECT DISTINCT s.vulnerability_id
        FROM stg_vulnerability_alias s
        LEFT JOIN vulnerability v ON v.vulnerability_id = s.vulnerability_id
        WHERE v.vulnerability_id IS NULL
        ORDER BY 1
        LIMIT 10
    """,
    upsert_sql="""
        INSERT INTO vulnerability_alias (vulnerability_id, alias)
        SELECT vulnerability_id, alias
        FROM stg_vulnerability_alias
        ON CONFLICT (vulnerability_id, alias) DO NOTHING
        RETURNING true AS inserted
    """,
)

VULNERABILITY_SEVERITY = TableSpec(
    table="vulnerability_severity",
    columns=(
        ("vulnerability_id", "TEXT"),
        ("severity_type", "TEXT"),
        ("vector", "TEXT"),
        ("origin", "TEXT"),
    ),
    key=("vulnerability_id", "severity_type", "vector"),
    unresolved_sql="""
        SELECT DISTINCT s.vulnerability_id
        FROM stg_vulnerability_severity s
        LEFT JOIN vulnerability v ON v.vulnerability_id = s.vulnerability_id
        WHERE v.vulnerability_id IS NULL
        ORDER BY 1
        LIMIT 10
    """,
    upsert_sql="""
        INSERT INTO vulnerability_severity AS t
            (vulnerability_id, severity_type, vector, origin)
        SELECT vulnerability_id, severity_type, vector, origin
        FROM stg_vulnerability_severity
        ON CONFLICT (vulnerability_id, severity_type, vector) DO UPDATE SET
            origin = EXCLUDED.origin
        WHERE t.origin IS DISTINCT FROM EXCLUDED.origin
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
LOAD_ORDER: tuple[TableSpec, ...] = (
    PACKAGE,
    RELEASE,
    DEPENDENCY,
    VULNERABILITY,
    VULNERABILITY_ALIAS,
    VULNERABILITY_SEVERITY,
    QUARANTINE,
    DATA_QUALITY_RESULT,
)


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