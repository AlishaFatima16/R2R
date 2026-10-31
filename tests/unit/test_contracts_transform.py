import pandas as pd

from pipeline.contracts.records import QuarantineRecord
from pipeline.transform import transform_osv, transform_pypi_project
from pipeline.transform.ranges import evaluate_ranges


def test_invalid_payload_is_quarantined():
    frames, quarantine = transform_pypi_project({"info": {}})
    assert frames == {}
    assert quarantine[0].reason_code == "missing_field"
    assert isinstance(quarantine[0], QuarantineRecord)


def test_pypi_transform_normalizes_and_preserves_invalid_requirement():
    frames, quarantine = transform_pypi_project({
        "info": {
            "name": "My_Package", "version": "1.0",
            "requires_dist": ["Requests>=2", "not a requirement"],
        },
        "releases": {"1.0": [{"filename": "x.whl", "upload_time": "2024-01-01T00:00:00Z"}]},
    })
    assert not quarantine
    assert frames["package"].loc[0, "canonical_name"] == "my-package"
    assert len(frames["dependency"]) == 2
    assert frames["dependency"]["requirement_valid"].tolist() == [True, False]


def test_osv_transform_evaluates_exposure():
    frames, quarantine = transform_osv({
        "id": "PYSEC-1", "modified": "2024-01-02T00:00:00Z",
        "affected": [{
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.32.0"}]}],
            "versions": ["2.31.0"],
        }],
    }, releases=pd.DataFrame([{"canonical_name": "requests", "version": "2.31.0"}]))
    assert not quarantine
    assert frames["affected_release"].loc[0, "in_range"]
    assert frames["affected_release"].loc[0, "in_enumerated"]


def test_range_fixed_is_exclusive_and_last_affected_inclusive():
    fixed = [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
    last = [{"events": [{"introduced": "0"}, {"last_affected": "2.0"}]}]
    assert evaluate_ranges("1.9", fixed) is True
    assert evaluate_ranges("2.0", fixed) is False
    assert evaluate_ranges("2.0", last) is True
