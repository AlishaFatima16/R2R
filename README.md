# R2R (Raw to Real)

ETL and EDA pipeline for PyPI supply-chain risk data. It extracts package, release, dependency and vulnerability data from public APIs, validates it with Pydantic, transforms it with Pandas, loads it into PostgreSQL, and supports structured exploratory data analysis. The output is designed to be reused as an ML-ready dataset in later projects.

**Status:** Week 1 - repository setup and API verification.

## Data sources

- PyPI JSON and Index (Simple) APIs
- OSV.dev
- deps.dev (v3)

Rate limits and some response details are still being verified. See `docs/`.

## Pipeline

API -> source adapters -> raw data zone -> Pydantic validation -> quarantine / Pandas transformation -> canonical model -> PostgreSQL -> SQL views -> EDA and quality reports -> ML-ready export

## Repository layout

| Path | Purpose |
|---|---|
| `src/pipeline/` | Pipeline code (adapters, raw, contracts, canonical, transform, quality, load, features) |
| `config/` | Configuration, including the seed package list |
| `migrations/` | Database schema migrations |
| `sql/` | Analytical views and marts |
| `fixtures/` | Saved API payloads for tests, including deliberately invalid ones |
| `tests/` | Unit, contract, database, idempotency and end-to-end tests |
| `notebooks/`, `reports/` | EDA notebooks and generated reports |
| `exports/` | ML-ready exports (generated, not committed) |
| `docs/` | Design docs, data dictionary, decisions |

## Getting started

Requires Python 3.11 or newer.

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy .env.example .env
```

Edit `.env` with your own values. Never commit `.env`.

Database setup (Docker) and pipeline commands will be added here once they exist.

## Working rules

- Work on a branch and open a pull request into `main`. Do not push to `main` directly.
- Every pull request needs one review from another team member.
- Never commit secrets, raw data or generated exports.
- Record design decisions in `docs/decisions.md`.