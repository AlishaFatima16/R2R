"""PyPI JSON API adapter: one request per package."""

from __future__ import annotations

from urllib.parse import quote

from pipeline.extract.http import HttpClient
from pipeline.extract.records import RawRecord, save_result

SOURCE = "pypi_json"
URL = "https://pypi.org/pypi/{name}/json"


def fetch_package(client: HttpClient, root, run_label: str, name: str) -> list[RawRecord]:
    """Fetch and save one package. A 404 is saved too (body null), so a replay knows."""
    result = client.request("GET", URL.format(name=name))
    return [save_result(root, SOURCE, run_label, name, result, None)]


VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"


def version_file_name(name: str, version: str) -> str:
    """File name for one release: the version is URL-quoted so any version is path-safe."""
    return f"{name}@{quote(version, safe='')}"


def fetch_version(
    client: HttpClient, root, run_label: str, name: str, version: str
) -> list[RawRecord]:
    """Fetch and save one release. Only this endpoint carries that release's requires_dist."""
    url = VERSION_URL.format(name=name, version=quote(version, safe=""))
    result = client.request("GET", url)
    file_name = version_file_name(name, version)
    return [save_result(root, SOURCE, run_label, file_name, result, None)]
