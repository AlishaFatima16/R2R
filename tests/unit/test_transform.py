import json
from pathlib import Path

import pandas as pd

from pipeline.load.tables import (
    DEPENDENCY,
    PACKAGE,
    RELEASE,
    VULNERABILITY,
    VULNERABILITY_ALIAS,
    VULNERABILITY_SEVERITY,
)
from pipeline.orchestrate import OsvPageItem, ProjectItem, ValidatedBatch, VersionItem
from pipeline.transform import transform
from pipeline.transform.pypi import transform_pypi_project
from pipeline.validate.osv import validate_osv_page
from pipeline.validate.pypi import validate_pypi_project, validate_pypi_version

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def loader_columns(spec) -> list[str]:
    return [name for name, _ in spec.columns]


def test_transform_uses_real_fixture_shapes_and_loader_columns():
    projects = []
    osv_pages = []
    for index, path in enumerate(sorted((FIXTURES / "pypi_json").glob("*.json"))):
        result = validate_pypi_project(json.loads(path.read_text()), index + 1)
        assert result.value is not None, result.quarantine
        projects.append(ProjectItem(path.stem, index + 1, result.value))
    for index, path in enumerate(sorted((FIXTURES / "osv").glob("*.json"))):
        result = validate_osv_page(json.loads(path.read_text()), index + 100)
        assert not result.quarantine, result.quarantine[:2]
        osv_pages.append(OsvPageItem(path.stem, index + 100, result.vulns))

    result = transform(ValidatedBatch(
        run_id=1,
        seed={item.name: "A" for item in projects},
        projects=projects,
        osv_pages=osv_pages,
    ))

    expected = {
        "package": PACKAGE,
        "release": RELEASE,
        "dependency": DEPENDENCY,
        "vulnerability": VULNERABILITY,
        "vulnerability_alias": VULNERABILITY_ALIAS,
        "vulnerability_severity": VULNERABILITY_SEVERITY,
    }
    assert set(result.frames) == set(expected)
    for table, spec in expected.items():
        assert list(result.frames[table].columns) == loader_columns(spec)


def test_pypi_transform_keeps_empty_release_frames_and_hashes_release_rows():
    frames, quarantine = transform_pypi_project(
        {"info": {"name": "Demo", "version": "1.0"}, "releases": {}},
        seed_tier="A",
    )
    assert not quarantine
    assert list(frames["release"].columns) == loader_columns(RELEASE)
    assert frames["release"].empty

    frames, quarantine = transform_pypi_project({
        "info": {"name": "Demo", "version": "1.0"},
        "releases": {"1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00"}]},
    }, seed_tier="A")
    assert not quarantine
    assert frames["release"].loc[0, "content_hash"]
    assert frames["release"].loc[0, "uploaded_at"].tzinfo is not None


def test_dependencies_use_per_release_response_and_create_invalid_rows():
    project_body = {
        "info": {"name": "Demo", "version": "2.0"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}],
            "2.0": [{"upload_time_iso_8601": "2024-01-02T00:00:00Z"}],
        },
    }
    release_body = {
        "info": {
            "name": "Demo", "version": "2.0",
            "requires_dist": ["Requests>=2", "invalid requirement"],
        },
        "urls": [],
    }
    project = validate_pypi_project(project_body).value
    release = validate_pypi_version(release_body).value
    frames = transform(ValidatedBatch(
        run_id=1,
        seed={"demo": "A"},
        projects=[ProjectItem("demo", 1, project)],
        versions=[
            VersionItem("demo", "2.0", 2, release)
        ],
    )).frames
    assert frames["release"]["deps_fetched"].tolist() == [False, True]
    assert frames["dependency"]["version"].tolist() == ["2.0", "2.0"]
    assert frames["dependency"]["target_name"].iloc[0] == "requests"
    assert pd.isna(frames["dependency"]["target_name"].iloc[1])


def test_extra_only_marker_requires_extra_to_be_the_only_environment():
    project_body = {
        "info": {"name": "Demo", "version": "1.0"},
        "releases": {"1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}]},
    }
    release_body = {
        "info": {
            "name": "Demo", "version": "1.0",
            "requires_dist": [
                "a; extra == 'security'",
                "b; extra == 'security' and python_version >= '3.11'",
            ],
        },
        "urls": [],
    }
    project = validate_pypi_project(project_body).value
    release = validate_pypi_version(release_body).value
    frames = transform(ValidatedBatch(
        run_id=1,
        seed={"demo": "A"},
        projects=[ProjectItem("demo", 1, project)],
        versions=[
            VersionItem("demo", "1.0", 2, release)
        ],
    )).frames
    assert frames["dependency"]["is_extra_only"].tolist() == [True, False]
