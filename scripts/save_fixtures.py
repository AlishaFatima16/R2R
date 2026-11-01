"""Save real API responses into fixtures/ so the whole team can see what the APIs return.

Run from the project root:
    python scripts/save_fixtures.py

For every package below it saves:
    fixtures/pypi_json/<name>.json   the PyPI JSON API response
    fixtures/osv/<name>.json         the OSV vulnerabilities for that package
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests

PACKAGES = [
    "requests",
    "flask",
    "django",
    "pillow",
    "pyyaml",
    "urllib3",
    "jinja2",
    "six",
]

PYPI_URL = "https://pypi.org/pypi/{name}/json"
OSV_URL = "https://api.osv.dev/v1/query"
HEADERS = {"User-Agent": "R2R-university-project"}
OUT = Path("fixtures")


def call(method: str, url: str, **kwargs):
    """One HTTP call that retries up to 3 times, waiting longer after each failure."""
    last_error = None
    for attempt in range(3):
        try:
            response = requests.request(method, url, timeout=30, headers=HEADERS, **kwargs)
            if response.status_code == 404:
                return response  # package does not exist: not worth retrying
            response.raise_for_status()
            return response
        except requests.RequestException as error:
            last_error = error
            wait = 2**attempt
            print(f"  problem ({error}); retrying in {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"gave up on {url}: {last_error}")


def save(folder: str, name: str, data) -> Path:
    path = OUT / folder / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


def fetch_pypi(name: str) -> None:
    response = call("GET", PYPI_URL.format(name=name))
    if response.status_code == 404:
        print(f"  {name}: not found on PyPI")
        return
    data = response.json()
    releases = data.get("releases", {})
    yanked = sum(1 for files in releases.values() for f in files if f.get("yanked"))
    save("pypi_json", name, data)
    print(f"  PyPI: {len(releases)} releases, {yanked} yanked files")


def fetch_osv(name: str) -> None:
    vulns = []
    body = {"package": {"name": name, "ecosystem": "PyPI"}}
    while True:
        data = call("POST", OSV_URL, json=body).json()
        vulns.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
        body = {**body, "page_token": token}  # OSV returns long answers in pages
    save("osv", name, {"vulns": vulns})
    print(f"  OSV: {len(vulns)} vulnerabilities")


def main() -> None:
    for name in PACKAGES:
        print(name)
        fetch_pypi(name)
        fetch_osv(name)
        time.sleep(0.5)  # be polite to the servers
    print(f"Done. Look inside the {OUT}/ folder.")


if __name__ == "__main__":
    main()