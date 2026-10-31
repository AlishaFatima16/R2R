"""Quality checks that return metrics instead of silently dropping records."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class QualityResult:
    check_name: str
    dimension: str
    table_name: str | None
    metric_value: float
    threshold: float | None
    passed: bool
    details: dict


def run_quality_checks(frames: dict[str, pd.DataFrame]) -> list[QualityResult]:
    results: list[QualityResult] = []
    package = frames.get("package")
    if package is not None and not package.empty:
        normalized = package["canonical_name"].map(canonicalize_name)
        results.append(QualityResult(
            "package_names_canonical", "validity", "package",
            float((normalized == package["canonical_name"]).mean()), 1.0,
            bool((normalized == package["canonical_name"]).all()), {},
        ))
    release = frames.get("release")
    if release is not None and not release.empty:
        duplicates = int(release.duplicated(["canonical_name", "version"]).sum())
        results.append(QualityResult(
            "release_natural_key_unique", "uniqueness", "release",
            float(duplicates), 0.0, duplicates == 0, {"duplicates": duplicates},
        ))
    dependency = frames.get("dependency")
    if dependency is not None and not dependency.empty:
        invalid = int((~dependency["requirement_valid"]).sum())
        results.append(QualityResult(
            "dependency_parse_rate", "validity", "dependency",
            float((len(dependency) - invalid) / len(dependency)), None, True,
            {"invalid_requirements": invalid},
        ))
    return results
