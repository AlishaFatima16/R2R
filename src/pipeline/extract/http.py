"""One HTTP client for every source: timeouts, retries, backoff, and a clear result.

Retried: network errors, HTTP 429 and 5xx, and bodies that are not valid JSON (for example
a truncated response). Not retried: 404, which is returned as a normal result with
body=None, and every other 4xx, which raises HttpError.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

import requests

USER_AGENT = "R2R-university-project (PyPI supply-chain observatory)"
MAX_RETRY_AFTER_SECONDS = 60


class HttpError(Exception):
    """The request failed for good (retries used up, or a non-retryable status)."""


@dataclass(frozen=True)
class HttpResult:
    url: str
    status: int
    body: object | None  # parsed JSON; None for a 404
    fetched_at: datetime


class HttpClient:
    def __init__(
        self,
        session=None,
        retries: int = 3,
        backoff: float = 1.0,
        timeout: float = 30.0,
        sleep=time.sleep,
    ):
        self.session = session if session is not None else requests.Session()
        self.retries = retries
        self.backoff = backoff
        self.timeout = timeout
        self.sleep = sleep

    def request(self, method: str, url: str, **kwargs) -> HttpResult:
        headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
        last_problem = "no attempt made"
        for attempt in range(self.retries):
            wait = self.backoff * 2**attempt
            try:
                response = self.session.request(
                    method, url, timeout=self.timeout, headers=headers, **kwargs
                )
            except requests.RequestException as error:
                last_problem = f"network error: {error}"
            else:
                status = response.status_code
                if status == 404:
                    return HttpResult(url, 404, None, datetime.now(UTC))
                if status == 429 or status >= 500:
                    last_problem = f"HTTP {status}"
                    wait = max(wait, self._retry_after(response))
                elif status >= 400:
                    raise HttpError(f"{method} {url}: HTTP {status}")
                else:
                    try:
                        body = response.json()
                    except ValueError as error:
                        last_problem = f"response is not valid JSON: {error}"
                    else:
                        return HttpResult(url, status, body, datetime.now(UTC))
            if attempt < self.retries - 1:
                self.sleep(wait)
        raise HttpError(f"{method} {url}: gave up after {self.retries} tries ({last_problem})")

    @staticmethod
    def _retry_after(response) -> float:
        value = response.headers.get("Retry-After", "")
        if value.isdigit():
            return min(float(value), MAX_RETRY_AFTER_SECONDS)
        return 0.0
