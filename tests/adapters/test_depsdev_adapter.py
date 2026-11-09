from pipeline.extract.depsdev import dependencies_url, fetch_dependencies
from pipeline.extract.http import HttpClient


class Reply:
    status_code = 200

    def __init__(self):
        self.headers = {}

    def json(self):
        return {"nodes": [], "edges": []}


class Session:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return Reply()


def test_url_quotes_package_and_version():
    assert dependencies_url("my package", "1.0+abc") == (
        "https://api.deps.dev/v3/systems/PYPI/packages/my%20package/versions/1.0%2Babc:dependencies"
    )


def test_fetch_uses_shared_client_and_saves_raw_response(tmp_path):
    session = Session()
    client = HttpClient(session=session)
    records = fetch_dependencies(client, tmp_path, "run1", "requests", "2.31.0")
    assert len(records) == 1
    assert records[0].source == "depsdev"
    assert session.calls[0][0] == "GET"
    assert ":dependencies" in session.calls[0][1]
