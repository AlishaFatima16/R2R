"""Fetch packages from PyPI and OSV and save the raw responses.

    python -m pipeline.extract.cli --packages requests flask
    python -m pipeline.extract.cli --packages-file config/seed.txt --run-label 2026-11-02

A packages file has one package name per line; blank lines and lines starting with # are
ignored. Running again with the same --run-label skips what is already saved.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from pipeline.extract.http import HttpClient
from pipeline.extract.run import ADAPTERS, extract_packages


def read_packages_file(path: Path) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--packages", nargs="*", default=[], help="package names")
    parser.add_argument("--packages-file", type=Path, help="one package name per line")
    parser.add_argument("--run-label", default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--root", type=Path, default=Path("."), help="project root")
    parser.add_argument("--sources", nargs="*", default=list(ADAPTERS), choices=list(ADAPTERS))
    args = parser.parse_args(argv)

    names = list(args.packages)
    if args.packages_file:
        names += read_packages_file(args.packages_file)
    if not names:
        parser.error("give --packages or --packages-file")

    result = extract_packages(
        names, HttpClient(), args.root, args.run_label, sources=tuple(args.sources)
    )
    print(
        f"run {args.run_label}: {len(result.records)} responses saved, "
        f"{len(result.skipped)} skipped, {len(result.failed)} failed"
    )
    return 1 if result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
