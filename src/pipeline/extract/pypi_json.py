"""PyPI JSON API adapter: one request per package."""

from __future__ import annotations

from pipeline.extract.http import HttpClient
from pipeline.extract.records import RawRecord, save_result

SOURCE = "pypi_json"
URL = "https://pypi.org/pypi/{name}/json"


def fetch_package(client: HttpClient, root, run_label: str, name: str) -> list[RawRecord]:
    """Fetch and save one package. A 404 is saved too (body null), so a replay knows."""
    result = client.request("GET", URL.format(name=name))
    return [save_result(root, SOURCE, run_label, name, result, None)]
