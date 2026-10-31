"""Save every API response to disk before anything else touches it.

One line of a gzip-compressed JSON-lines file per response:
    data/raw/<source>/<run_label>/<name>.jsonl.gz
The line holds the request, the HTTP status, the fetch time and the parsed response body.
Lines are only appended, never rewritten, so a raw file can always be replayed.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SAFE_NAME = re.compile(r"[A-Za-z0-9._%@-]+")


@dataclass(frozen=True)
class RawRef:
    file_path: str  # relative, with forward slashes, as stored in raw_object.file_path
    line_number: int  # 1-based
    sha256: str  # hash of the response body


def body_sha256(body) -> str:
    """A stable hash: the same body always gives the same hash, whatever the key order."""
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def raw_file_path(source: str, run_label: str, name: str) -> str:
    for part in (source, run_label, name):
        if not SAFE_NAME.fullmatch(part) or part in (".", ".."):
            raise ValueError(f"unsafe name for a file path: {part!r}")
    return f"data/raw/{source}/{run_label}/{name}.jsonl.gz"


def raw_file_exists(root: Path, source: str, run_label: str, name: str) -> bool:
    return (Path(root) / raw_file_path(source, run_label, name)).exists()


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def write_line(root: Path, source: str, run_label: str, name: str, record: dict) -> RawRef:
    """Append one record. record must contain a "body" key (the response body)."""
    relative = raw_file_path(source, run_label, name)
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    line_number = count_lines(path) + 1
    text = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    with gzip.open(path, "ab") as handle:
        handle.write((text + "\n").encode("utf-8"))
    return RawRef(relative, line_number, body_sha256(record["body"]))


def read_lines(root: Path, file_path: str) -> list[dict]:
    with gzip.open(Path(root) / file_path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]
