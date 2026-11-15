"""Unit tests for the quality checks (no database needed)."""

import pandas as pd

from pipeline.quality.rules import RESULT_COLUMNS, quality_frame, run_quality_checks


def _frames():
    return {
        "package": pd.DataFrame(
            {"canonical_name": ["flask", "Bad_Name"], "in_seed": [True, False]}
        ),
        "release": pd.DataFrame(
            {"canonical_name": ["flask", "flask"], "version": ["1.0", "1.0"],
             "version_valid": [True, None]}
        ),
        "dependency": pd.DataFrame({"requirement_valid": [True, False, True, True]}),
        "vulnerability": pd.DataFrame(
            {"dates_out_of_order": [False, True],
             "published_at": [pd.Timestamp("2024-01-01"), None]}
        ),
        "affected_release": pd.DataFrame({"in_range": [True, None, False, True]}),
    }


def _by_name(results):
    return {result.check_name: result for result in results}


def test_each_check_reports_rate_threshold_and_pass_flag():
    checks = _by_name(run_quality_checks(_frames()))
    assert checks["package_names_canonical"].passed is False
    assert checks["package_names_canonical"].metric_value == 0.5
    assert checks["release_natural_key_unique"].metric_value == 1.0
    assert checks["release_natural_key_unique"].passed is False
    assert checks["dependency_parse_rate"].metric_value == 0.75
    assert checks["dependency_parse_rate"].details["invalid_requirements"] == 1
    assert checks["advisory_dates_in_order"].metric_value == 0.5
    assert checks["advisory_has_publication_date"].details["missing"] == 1
    assert checks["affected_release_range_evaluated"].metric_value == 0.75
    assert checks["seed_packages_have_releases"].passed is True


def test_missing_flag_values_count_as_false_not_as_errors():
    checks = _by_name(run_quality_checks(_frames()))
    assert checks["release_version_valid"].metric_value == 0.5


def test_frame_has_loader_columns_and_python_booleans():
    frame = quality_frame(_frames())
    assert list(frame.columns) == list(RESULT_COLUMNS)
    assert all(isinstance(value, bool) for value in frame["passed"])
    assert all(isinstance(value, dict) for value in frame["details"])


def test_empty_input_gives_empty_frame_with_columns():
    frame = quality_frame({})
    assert frame.empty
    assert list(frame.columns) == list(RESULT_COLUMNS)
