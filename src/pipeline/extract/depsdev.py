"""deps.dev v3 adapter for resolved PyPI dependency graphs."""
from __future__ import annotations

from urllib.parse import quote

from pipeline.extract.http import HttpClient
from pipeline.extract.records import RawRecord, save_result

SOURCE = "depsdev"
BASE_URL = "https://api.deps.dev/v3/systems/PYPI/packages/{name}/versions/{version}:dependencies"


def dependencies_url(name: str, version: str) -> str:
    """Build a path-safe deps.dev GetDependencies URL."""
    if not name.strip() or not version.strip():
        raise ValueError("package name and version must not be empty")
    return BASE_URL.format(name=quote(name, safe=""), version=quote(version, safe=""))


def fetch_dependencies(
    client: HttpClient, root, run_label: str, name: str, version: str
) -> list[RawRecord]:
    """Fetch and persist the resolved graph for one exact PyPI release."""
    url = dependencies_url(name, version)
    result = client.request("GET", url)
    label = f"{name}@{version}"
    return [save_result(root, SOURCE, run_label, label, result, None)]
