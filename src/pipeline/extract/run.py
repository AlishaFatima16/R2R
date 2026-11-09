"""Fetch many packages from the chosen sources. One bad package never stops the run."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial

from pipeline.extract import depsdev, osv, pypi_json
from pipeline.extract.http import HttpClient, HttpError
from pipeline.extract.names import canonical_name
from pipeline.extract.raw_writer import raw_file_exists, raw_file_path, read_lines
from pipeline.extract.records import RawRecord
from pipeline.extract.select_versions import select_versions

ADAPTERS = {
    pypi_json.SOURCE: pypi_json.fetch_package,
    osv.SOURCE: osv.fetch_package,
}
DEFAULT_RELEASE_LIMIT = 30


@dataclass
class ExtractResult:
    records: list[RawRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


def saved_bodies(root, source: str, run_label: str, name: str) -> list[dict]:
    """The response bodies already saved for one package (used when resuming)."""
    lines = read_lines(root, raw_file_path(source, run_label, name))
    return [line["body"] for line in lines if line.get("body") is not None]


def _fetch(result, key, fetch, root, source, run_label, file_name, log) -> bool:
    """Run one fetch unless it is already saved. Returns False if it failed."""
    if raw_file_exists(root, source, run_label, file_name):
        result.skipped.append(key)
        return True

    try:
        result.records.extend(fetch())
    except HttpError as error:
        result.failed[key] = str(error)
        log(f"FAILED {key}: {error}")
        return False

    log(f"saved  {key}")
    return True


def extract_packages(
    names,
    client: HttpClient,
    root,
    run_label: str,
    sources=(pypi_json.SOURCE, osv.SOURCE),
    release_limit: int | None = DEFAULT_RELEASE_LIMIT,
    log=print,
) -> ExtractResult:
    """Fetch package data, selected release data, and optional deps.dev graphs.

    deps.dev is fetched once for each selected release when included in sources.
    Existing files are skipped so interrupted runs can resume.
    """
    result = ExtractResult()

    package_sources = [source for source in sources if source != depsdev.SOURCE]

    for raw_name in names:
        name = canonical_name(raw_name)
        project_ok = True

        for source in package_sources:
            fetch = ADAPTERS[source]
            ok = _fetch(
                result,
                f"{source}:{name}",
                partial(fetch, client, root, run_label, name),
                root,
                source,
                run_label,
                name,
                log,
            )
            project_ok = project_ok and ok

        if release_limit is None or pypi_json.SOURCE not in sources or not project_ok:
            continue

        projects = saved_bodies(root, pypi_json.SOURCE, run_label, name)
        if not projects:
            continue

        osv_bodies = (
            saved_bodies(root, osv.SOURCE, run_label, name)
            if osv.SOURCE in sources
            else []
        )

        for version in select_versions(projects[0], osv_bodies, release_limit):
            file_name = pypi_json.version_file_name(name, version)

            _fetch(
                result,
                f"{pypi_json.SOURCE}:{file_name}",
                partial(
                    pypi_json.fetch_version,
                    client,
                    root,
                    run_label,
                    name,
                    version,
                ),
                root,
                pypi_json.SOURCE,
                run_label,
                file_name,
                log,
            )

            if depsdev.SOURCE in sources:
                _fetch(
                    result,
                    f"{depsdev.SOURCE}:{file_name}",
                    partial(
                        depsdev.fetch_dependencies,
                        client,
                        root,
                        run_label,
                        name,
                        version,
                    ),
                    root,
                    depsdev.SOURCE,
                    run_label,
                    file_name,
                    log,
                )

    return result