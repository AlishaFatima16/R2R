"""Fetch many packages from the chosen sources. One bad package never stops the run."""

from __future__ import annotations

from dataclasses import dataclass, field

from pipeline.extract import osv, pypi_json
from pipeline.extract.http import HttpClient, HttpError
from pipeline.extract.names import canonical_name
from pipeline.extract.raw_writer import raw_file_exists
from pipeline.extract.records import RawRecord

ADAPTERS = {pypi_json.SOURCE: pypi_json.fetch_package, osv.SOURCE: osv.fetch_package}


@dataclass
class ExtractResult:
    records: list[RawRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # "<source>:<name>" already saved
    failed: dict[str, str] = field(default_factory=dict)  # "<source>:<name>" -> reason


def extract_packages(
    names,
    client: HttpClient,
    root,
    run_label: str,
    sources=(pypi_json.SOURCE, osv.SOURCE),
    log=print,
) -> ExtractResult:
    """Resume rule: if a raw file for (source, package) already exists in this run_label,
    that package is skipped. Use a new run_label to fetch everything again."""
    result = ExtractResult()
    for raw_name in names:
        name = canonical_name(raw_name)
        for source in sources:
            key = f"{source}:{name}"
            if raw_file_exists(root, source, run_label, name):
                result.skipped.append(key)
                continue
            try:
                result.records.extend(ADAPTERS[source](client, root, run_label, name))
            except HttpError as error:
                result.failed[key] = str(error)
                log(f"FAILED {key}: {error}")
            else:
                log(f"saved  {key}")
    return result
