from collections import Counter
from pathlib import Path
import re


SEED_FILE = Path(__file__).resolve().parents[2] / "config" / "seed.txt"


def test_seed_file_has_expected_tiers_and_canonical_names():
    rows = []

    for line in SEED_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(",")
        assert len(parts) == 2, f"Invalid seed line: {line}"

        name, tier = (part.strip() for part in parts)
        rows.append((name, tier))

    names = [name for name, _ in rows]
    tier_counts = Counter(tier for _, tier in rows)

    assert len(rows) == 120
    assert tier_counts == {"A": 80, "B": 40}
    assert len(names) == len(set(names)), "Duplicate package names found"

    canonical_name_pattern = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    assert all(
        canonical_name_pattern.fullmatch(name) for name in names
    ), "Non-canonical package name found"