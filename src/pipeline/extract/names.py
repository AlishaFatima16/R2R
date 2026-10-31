"""Package-name helpers."""

from __future__ import annotations

import re


def canonical_name(name: str) -> str:
    """The PEP 503 normalized name: lower case, runs of - _ . become one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()
