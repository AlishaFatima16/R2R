"""Quality checks that return metrics instead of silently dropping records.

Each check measures a rate or a count over the frames about to be loaded, compares it with a
threshold, and says whether it passed. Results are stored in ``data_quality_result`` so the
dashboard can show them. A failed check does not stop the run: it is evidence about the data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import pandas as pd
from packaging.utils import canonicalize_name

RESULT_COLUMNS = (
    "check_name", "dimension", "table_name", "metric_value", "threshold", "passed", "details",
)


@dataclass(frozen=True)
class QualityResult:
    check_name: str
    dimension: str
    table_name: str | None
    metric_value: float
    threshold: float | None
    passed: bool
    details: dict


def _flag(series: pd.Series) -> pd.Series:
    """A boolean flag column where missing values count as False."""
    return series.fillna(False).astype(bool)


def _rate_check(
    name: str, dimension: str, table: str, good: pd.Series, threshold: float, details: dict
) -> QualityResult:
    rate = float(good.mean())
    return QualityResult(name, dimension, table, rate, threshold, rate >= threshold, details)


def run_quality_checks(frames: dict[str, pd.DataFrame]) -> list[QualityResult]:
    results: list[QualityResult] = []

    package = frames.get("package")
    release = frames.get("release")
    dependency = frames.get("dependency")
    vulnerability = frames.get("vulnerability")
    affected_release = frames.get("affected_release")

    if package is not None and not package.empty:
        canonical = package["canonical_name"] == package["canonical_name"].map(canonicalize_name)
        results.append(_rate_check(
            "package_names_canonical", "validity", "package", canonical, 1.0,
            {"rows": len(package)},
        ))
        if release is not None and "in_seed" in package.columns:
            seed = set(package.loc[_flag(package["in_seed"]), "canonical_name"])
            if seed:
                with_releases = seed & set(release["canonical_name"])
                results.append(_rate_check(
                    "seed_packages_have_releases", "completeness", "package",
                    pd.Series([name in with_releases for name in sorted(seed)]), 1.0,
                    {"seed_packages": len(seed), "missing": sorted(seed - with_releases)[:10]},
                ))

    if release is not None and not release.empty:
        duplicates = release.duplicated(["canonical_name", "version"]).sum().item()
        results.append(QualityResult(
            "release_natural_key_unique", "uniqueness", "release",
            float(duplicates), 0.0, duplicates == 0, {"duplicates": duplicates},
        ))
        if "version_valid" in release.columns:
            results.append(_rate_check(
                "release_version_valid", "validity", "release", _flag(release["version_valid"]),
                0.99, {"rows": len(release)},
            ))

    if dependency is not None and not dependency.empty and "requirement_valid" in dependency:
        valid = _flag(dependency["requirement_valid"])
        results.append(_rate_check(
            "dependency_parse_rate", "validity", "dependency", valid, 0.95,
            {"invalid_requirements": (~valid).sum().item(), "rows": len(dependency)},
        ))

    if vulnerability is not None and not vulnerability.empty:
        if "dates_out_of_order" in vulnerability.columns:
            in_order = ~_flag(vulnerability["dates_out_of_order"])
            results.append(_rate_check(
                "advisory_dates_in_order", "consistency", "vulnerability", in_order, 0.99,
                {"out_of_order": (~in_order).sum().item(), "rows": len(vulnerability)},
            ))
        if "published_at" in vulnerability.columns:
            has_date = vulnerability["published_at"].notna()
            results.append(_rate_check(
                "advisory_has_publication_date", "completeness", "vulnerability", has_date, 0.99,
                {"missing": (~has_date).sum().item(), "rows": len(vulnerability)},
            ))

    if affected_release is not None and not affected_release.empty:  # noqa: SIM102
        if "in_range" in affected_release.columns:
            evaluated = affected_release["in_range"].notna()
            results.append(_rate_check(
                "affected_release_range_evaluated", "completeness", "affected_release",
                evaluated, 0.9,
                {"not_evaluated": (~evaluated).sum().item(), "rows": len(affected_release)},
            ))

    return results


def quality_frame(frames: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """The quality results as a frame in the loader's ``data_quality_result`` shape."""
    rows = [asdict(result) for result in run_quality_checks(frames)]
    return pd.DataFrame(rows, columns=list(RESULT_COLUMNS))
