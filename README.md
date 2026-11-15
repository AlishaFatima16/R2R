# R2R (Raw to Real): PyPI Supply-Chain Risk Observatory

An ETL and EDA pipeline for Python supply-chain risk. It pulls package, release, dependency and advisory data from public APIs, validates it with Pydantic, transforms it with pandas, loads it into PostgreSQL, and serves the results in a web dashboard. The output is designed to be reused as an ML-ready dataset in later projects.

**Live dashboard:** https://alishafatima16.github.io/R2R/

## What it answers

For about 120 popular PyPI packages (tier A: most downloaded; tier B: extra packages with many advisories): which releases were affected by a published vulnerability, for how long, how fast fixes arrived, and how deep the dependency trees reach. Prevalence statistics use tier A only, because tier B was picked for having many advisories.

## Data sources

- PyPI JSON API (project and per-release)
- OSV.dev advisories
- deps.dev v3 (resolved dependency graphs)

## Pipeline

```text
APIs -> source adapters -> raw files (data/raw, never committed) -> Pydantic validation
     -> quarantine (bad records, with a reason) / pandas transform -> PostgreSQL
     -> SQL views -> dashboard export (JSON) -> static web app
```

Stage contracts are in [`docs/interfaces.md`](docs/interfaces.md); the data dictionary is in [`docs/data_dictionary.md`](docs/data_dictionary.md).

## Repository layout

| Path | Purpose |
|---|---|
| `src/pipeline/` | extract, validate, transform, load, orchestrate |
| `config/` | settings and the seed package list (`seed.txt`) |
| `migrations/` | database schema |
| `sql/` | analytical views and functions |
| `fixtures/` | saved API payloads for tests, including invalid ones |
| `tests/` | unit and database tests |
| `scripts/` | dashboard export and fixture tools |
| `dashboard/` | static web app and its exported data |
| `docs/` | design docs, interfaces, data dictionary |

## Quickstart

Requires Python 3.11 or newer and PostgreSQL 16. Commands are for Windows PowerShell; on Linux or macOS use `source .venv/bin/activate` and `export` instead of `$env:`.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy .env.example .env
```

1. **Create a database.** Use a local PostgreSQL install, or Docker:
   `docker run --name r2r-db -e POSTGRES_PASSWORD=<password> -e POSTGRES_DB=r2r -p 5432:5432 -d postgres:16`
2. **Point the project at it** (never commit `.env`):
   `$env:DATABASE_URL = "postgresql://postgres:<password>@localhost:5432/r2r"`
3. **Create the schema and views:**
   ```powershell
   python -m pipeline.load.migrate
   Get-ChildItem sql\functions\*.sql, sql\views\*.sql | ForEach-Object { psql $env:DATABASE_URL -v ON_ERROR_STOP=1 -f $_.FullName }
   ```
4. **Run the pipeline** (fetches live data; the full seed list takes about an hour and is resumable with the same `--run-label`):
   ```powershell
   python -m pipeline.orchestrate --seed-file config\seed.txt --run-label full1
   ```
   A quick test with two packages: `python -m pipeline.orchestrate --packages six:A flask:B --release-limit 5`
5. **Export the dashboard data and preview it:**
   ```powershell
   python scripts\export_dashboard_data.py
   cd dashboard; python -m http.server 8000
   ```
   Then open http://localhost:8000. See [`dashboard/README.md`](dashboard/README.md).

Run the tests with `python -m pytest tests`. The database tests need an **empty** database, so point `DATABASE_URL` at a separate one (for example `r2r_test`) while testing. CI (GitHub Actions) runs lint, migrations (twice, to prove they are idempotent) and the tests on Python 3.12 and 3.14.

## Reference run (15 Nov 2026)

120 seed packages, 1,058 packages in total (with dependency stubs), about 20,400 releases, 77,000 dependencies, 2,422 advisories, 705,943 release-vs-advisory rows, and 42,340 resolved dependency nodes (depth up to 7). Re-running on a loaded database changes nothing (idempotent loads). Counts will drift because PyPI and OSV are live sources.

## How the data is kept honest

- Every fetched response is saved raw, with a hash, and registered in the database (`raw_object`).
- Invalid records are never loaded and never silently dropped: they go to `quarantine` with a reason code and the field.
- Loads are idempotent (`content_hash` plus `ON CONFLICT`) and transactional.
- One advisory can affect many packages, so duplicates are removed by natural key before loading.

## Known limits

- The resolved dependency graph (deps.dev) is the **current** state and is not a historical feature.
- Some deps.dev graphs lack a root node and are quarantined.
- GIT-type advisory ranges are stored but cannot be matched to release versions.
- `data_quality_result` checks are defined but were not loaded in the reference run.

## Working rules

- Work on a branch and open a pull request into `main`. Every pull request needs one review from another team member.
- Never commit secrets, raw data or generated exports.
- Record design decisions in `docs/decisions.md`.

## Team

Alisha Fatima (database, integration, CI, fetchers and validation), Talha (sources, seed list, dashboard hosting), Subhan (validation and transform), Iza (analytics and SQL views).
