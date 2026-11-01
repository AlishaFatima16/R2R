"""What a source adapter hands to the rest of the pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pipeline.extract.http import HttpResult
from pipeline.extract.raw_writer import RawRef, write_line


@dataclass(frozen=True)
class RawRecord:
    """One saved response. The fields match pipeline.load.runs.register_raw_object."""

    source: str
    request_url: str
    request_params: dict | None
    http_status: int
    fetched_at: datetime
    sha256: str
    file_path: str
    line_number: int

    def as_kwargs(self) -> dict:
        """Use as: register_raw_object(conn, run_id, **record.as_kwargs())"""
        return {
            "source": self.source,
            "request_url": self.request_url,
            "request_params": self.request_params,
            "http_status": self.http_status,
            "fetched_at": self.fetched_at,
            "sha256": self.sha256,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


def save_result(
    root, source: str, run_label: str, name: str, result: HttpResult, params: dict | None
) -> RawRecord:
    record = {
        "source": source,
        "request_url": result.url,
        "request_params": params,
        "http_status": result.status,
        "fetched_at": result.fetched_at.isoformat(),
        "body": result.body,
    }
    ref: RawRef = write_line(root, source, run_label, name, record)
    return RawRecord(
        source=source,
        request_url=result.url,
        request_params=params,
        http_status=result.status,
        fetched_at=result.fetched_at,
        sha256=ref.sha256,
        file_path=ref.file_path,
        line_number=ref.line_number,
    )
