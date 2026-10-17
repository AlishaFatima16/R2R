"""Apply SQL migrations in order and record them in the schema_migration table.

Usage (from the repository root, with the virtual environment active):
    python -m pipeline.load.migrate             # apply pending migrations
    python -m pipeline.load.migrate --status    # show applied and pending, change nothing

Migration files live in migrations/ and are named NNN_description.sql
(three digits, applied in numeric order). Each file must manage its own
transaction (BEGIN ... COMMIT). An applied file must never be edited:
add a new migration instead. The runner refuses to continue if the content
of an already-applied file has changed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

import psycopg
from dotenv import load_dotenv

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "migrations"

TRACKING_DDL = """
CREATE TABLE IF NOT EXISTS schema_migration (
    filename   TEXT PRIMARY KEY,
    checksum   CHAR(64) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def checksum(path: Path) -> str:
    """SHA-256 of the file with line endings normalised, so Windows (CRLF)
    and Linux (LF) checkouts of the same file give the same value."""
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def migration_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("[0-9][0-9][0-9]_*.sql"))


def applied_migrations(conn) -> dict[str, str]:
    rows = conn.execute("SELECT filename, checksum FROM schema_migration").fetchall()
    return {filename: stored.strip() for filename, stored in rows}


def run(directory: Path, database_url: str, status_only: bool = False) -> int:
    files = migration_files(directory)
    if not files:
        print(f"No migration files found in {directory}")
        return 1

    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute(TRACKING_DDL)
        done = applied_migrations(conn)

        for path in files:
            if path.name in done and done[path.name] != checksum(path):
                print(
                    f"ERROR: {path.name} was already applied but its content has changed.\n"
                    "Do not edit applied migrations. Revert the change and add a new migration."
                )
                return 1

        pending = [p for p in files if p.name not in done]

        if status_only:
            for path in files:
                print(f"{'applied ' if path.name in done else 'pending '} {path.name}")
            return 0

        if not pending:
            print("Database is up to date.")
            return 0

        for path in pending:
            print(f"Applying {path.name} ...")
            conn.execute(path.read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO schema_migration (filename, checksum) VALUES (%s, %s)",
                (path.name, checksum(path)),
            )
        print(f"Applied {len(pending)} migration(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply R2R database migrations.")
    parser.add_argument("--status", action="store_true", help="show status and exit")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="migrations directory")
    parser.add_argument("--database-url", default=None, help="overrides DATABASE_URL")
    args = parser.parse_args(argv)

    load_dotenv()
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is not set. Copy .env.example to .env and fill it in.")
        return 2

    return run(args.dir, database_url, status_only=args.status)


if __name__ == "__main__":
    sys.exit(main())