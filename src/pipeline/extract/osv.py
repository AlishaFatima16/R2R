"""OSV.dev adapter: all advisories for one PyPI package, following the paging."""

from __future__ import annotations

from pipeline.extract.http import HttpClient
from pipeline.extract.records import RawRecord, save_result

SOURCE = "osv"
URL = "https://api.osv.dev/v1/query"
MAX_PAGES = 200  # a safety stop, so a bad token can never loop forever


def fetch_package(client: HttpClient, root, run_label: str, name: str) -> list[RawRecord]:
    """Fetch every page of advisories for one package. Each page is one saved line.

    All pages are fetched before anything is written. If a page fails, nothing is saved,
    so a half-finished file can never be mistaken for a complete one on resume.
    """
    pages = []
    params = {"package": {"name": name, "ecosystem": "PyPI"}}
    for _ in range(MAX_PAGES):
        result = client.request("POST", URL, json=params)
        pages.append((params, result))
        token = result.body.get("next_page_token") if isinstance(result.body, dict) else None
        if not token:
            return [save_result(root, SOURCE, run_label, name, r, p) for p, r in pages]
        params = {**params, "page_token": token}
    raise RuntimeError(f"{name}: more than {MAX_PAGES} pages from OSV, stopping")
