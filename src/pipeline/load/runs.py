"""Pipeline runs and the raw-object manifest.

Every execution is one row in pipeline_run. Every saved API response is one row in
raw_object. Both are written and committed immediately, so they survive a failed load.
"""

from __future__ import annotations

from datetime import datetime

from psycopg.types.json import Jsonb

from pipeline.load.loader import LoadError

FINAL_STATUSES = ("succeeded", "failed", "aborted")


def start_run(conn, git_commit: str, config_hash: str, notes: str | None = None) -> int:
    """Create a pipeline_run with status 'running' and return its run_id."""
    if len(config_hash) != 64:
        raise LoadError("config_hash must be 64 characters (SHA-256 hex)")
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO pipeline_run (started_at, status, git_commit, config_hash, notes) "
            "VALUES (now(), 'running', %s, %s, %s) RETURNING run_id",
            (git_commit, config_hash, notes),
        ).fetchone()
    return row[0]


def finish_run(conn, run_id: int, status: str, notes: str | None = None) -> None:
    """Mark a running pipeline_run as succeeded, failed or aborted."""
    if status not in FINAL_STATUSES:
        raise LoadError(f"status must be one of {FINAL_STATUSES}, got {status!r}")
    with conn.transaction():
        row = conn.execute(
            "UPDATE pipeline_run SET status = %s, finished_at = now(), "
            "notes = COALESCE(%s, notes) "
            "WHERE run_id = %s AND status = 'running' RETURNING run_id",
            (status, notes, run_id),
        ).fetchone()
        if row is None:
            raise LoadError(f"run {run_id} is not running (unknown id or already finished)")


def register_raw_object(
    conn,
    run_id: int,
    source: str,
    request_url: str,
    http_status: int,
    fetched_at: datetime,
    sha256: str,
    file_path: str,
    line_number: int,
    request_params: dict | None = None,
) -> tuple[int, bool]:
    """Record one saved API response. Returns (raw_object_id, created).

    An identical response (same source, URL and sha256) is not recorded twice: the
    existing id is returned with created=False.
    """
    if len(sha256) != 64:
        raise LoadError("sha256 must be 64 characters (hex)")
    params = Jsonb(request_params) if request_params is not None else None
    with conn.transaction():
        found = conn.execute("SELECT source_id FROM source WHERE name = %s", (source,)).fetchone()
        if found is None:
            raise LoadError(f"unknown source {source!r}")
        source_id = found[0]
        row = conn.execute(
            "INSERT INTO raw_object (run_id, source_id, request_url, request_params, "
            "http_status, fetched_at, sha256, file_path, line_number) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (source_id, request_url, sha256) DO NOTHING "
            "RETURNING raw_object_id",
            (run_id, source_id, request_url, params, http_status, fetched_at,
             sha256, file_path, line_number),
        ).fetchone()
        if row is not None:
            return row[0], True
        existing = conn.execute(
            "SELECT raw_object_id FROM raw_object "
            "WHERE source_id = %s AND request_url = %s AND sha256 = %s",
            (source_id, request_url, sha256),
        ).fetchone()
        return existing[0], False