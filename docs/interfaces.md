# Interfaces between pipeline stages

Owner: M3. Status: **v1.0, as implemented** (reference run of 15 Nov 2026). Change it only by pull request and tag the affected owner.

This file defines what each stage hands to the next. Table definitions come from the project blueprint (Section 7) and from `migrations/001_initial_schema.sql`.

## 1. Stages and owners

| Stage | Code | Input | Output |
|---|---|---|---|
| Extract | `src/pipeline/extract/` | seed list, config | raw files + `raw_object` manifest rows |
| Validate | `src/pipeline/validate/` | raw responses | valid records, quarantine rows |
| Transform | `src/pipeline/transform/` | valid records | one DataFrame per table (section 4) |
| Load | `src/pipeline/load/` | DataFrames, quarantine rows | PostgreSQL tables |
| Orchestrate | `src/pipeline/orchestrate.py` | seed list | one run, end to end |
| Analyse | `sql/`, `scripts/export_dashboard_data.py` | database views | EDA, dashboard data |

Rules for every stage:
- No stage calls the network except Extract.
- Every stage can be tested from saved fixtures, with no API needed (Load needs PostgreSQL).
- A stage never deletes data. Hard failures go to quarantine; soft problems become boolean flags.

## 2. Extract -> Validate

### Seed list
`config/seed.txt`: one line per package, `name,tier`. Tier is **A** (most-downloaded, representative) or **B** (extra packages with many advisories). The database allows only these two values. Lines starting with `#` are ignored. Prevalence statistics use tier A only.

### Sources and what is fetched per package
| Source | Request | Saved as |
|---|---|---|
| `pypi_json` | project JSON `/pypi/<name>/json` | `<name>` |
| `pypi_json` | **per-release JSON** `/pypi/<name>/<version>/json` | `<name>@<url-quoted version>` |
| `osv` | `POST /v1/query` for the package, all pages (`next_page_token`) | `<name>` |
| `depsdev` | resolved dependency graph of a release | `<name>@<version>` |

The project JSON lists `requires_dist` for the **latest release only**, so dependencies need the per-release JSON. The releases fetched per package are the 30 most recent plus every version named in an OSV `introduced`, `fixed` or `last_affected` event (GIT ranges are skipped). A 404 is saved with `body: null`, never dropped.

### Raw files
Path: `data/raw/<source>/<run_label>/<name>.jsonl.gz` (the `data/` folder is never committed).
One line per HTTP response:

```json
{"source": "osv", "request_url": "...", "request_params": {}, "http_status": 200,
 "fetched_at": "2026-11-15T10:30:00Z", "body": { }}
```

`sha256` is computed over the canonical JSON of the line and stored in the manifest. Each response gets one `raw_object` row (`run_id`, `source_id`, `request_url`, `request_params`, `http_status`, `fetched_at`, `sha256`, `file_path`, `line_number`). Identical re-fetches are detected by the unique key (`source_id`, `request_url`, `sha256`).

Re-using a `--run-label` resumes a run (files already saved are not fetched again). `--skip-fetch` replays saved files only.

### Python interface (implemented)

```python
# pipeline.orchestrate
def scan_raw(root, run_label) -> list[RawRecord]      # reads saved files, never the network
RawRecord.as_kwargs()                                 # matches pipeline.load.runs.register_raw_object
```

## 3. Validate and quarantine

Pydantic contracts live in `src/pipeline/validate/` (`pypi.py`, `osv.py`, `depsdev.py`) and `src/pipeline/contracts/`. A response either validates or produces quarantine rows. **Quarantine rows are plain dicts**:

```python
{
  "raw_object_id": int | None,
  "stage": "validate",          # 'validate' | 'transform' | 'load'
  "reason_code": str,
  "field_path": str | None,
  "message": str | None,
}
```

Implemented reason codes: `missing_field`, `type_error`, `invalid_timestamp`, `invalid_value`. In the reference run the only quarantined records were deps.dev graphs that did not contain their root node (`invalid_value`, field `nodes`).

One bad advisory in a page does not reject the page: each advisory is validated on its own.

Soft problems do not quarantine. They are flags on the row: `version_valid`, `requirement_valid`, `dates_out_of_order`, `is_conditional`, `is_extra_only`.

## 4. Transform -> Load

`transform(batch: ValidatedBatch) -> TransformResult(frames, quarantine)`, where `frames` is `dict[str, pandas.DataFrame]` keyed by table name. Each DataFrame has the columns of that table, minus surrogate keys.

Key rules:
- **The transform does not assign surrogate IDs.** Frames carry natural keys; the loader resolves `package_id`, `release_id` and so on.
- All timestamps are timezone-aware UTC. Package names are normalised (PEP 503). Versions are kept as published text.
- `content_hash` (SHA-256 hex) is computed over a row's mutable business columns in a fixed order; the loader uses it to skip unchanged rows.
- Missing values are `None`, never an empty string.
- **Duplicates are removed before loading** (`_dedupe` in `transform/__init__.py`): one advisory is returned for every package it affects, so the same `vulnerability_id` arrives several times. Rows are de-duplicated by each table's natural key; for rows with `modified_at`, the newest wins. The loader still refuses duplicate keys in one batch.
- Dependencies that point to packages outside the seed get a stub `package` row (`in_seed = false`, `seed_tier` null). Only seed packages have a tier.

### Natural keys by table

| Table | Natural key in the frame | Notes |
|---|---|---|
| source | `name` | seeded by migration |
| pipeline_run | (created by loader) | `runs.start_run` / `finish_run` |
| raw_object | (source, request_url, sha256) | `runs.register_raw_object` |
| quarantine | none, append-only | linked by `raw_object_id` |
| data_quality_result | (run_id, check_name, table_name) | rules in `quality/rules.py` |
| package | `canonical_name` | seed packages plus dependency stubs |
| release | (`canonical_name`, `version`) | |
| dependency | (`canonical_name`, `version`, `raw_requirement`) | carries `target_name`, null if the requirement is invalid |
| vulnerability | `vulnerability_id` | |
| vulnerability_alias | (`vulnerability_id`, `alias`) | insert-only |
| vulnerability_severity | (`vulnerability_id`, `severity_type`, `vector`) | |
| affected_package | (`vulnerability_id`, `entry_index`) | carries `package_name`; loader resolves `package_id` |
| affected_range | (`vulnerability_id`, `entry_index`, `range_index`) | `range_index` is in the schema |
| affected_event | (`vulnerability_id`, `entry_index`, `range_index`, `event_order`) | event types: introduced, fixed, last_affected, limit |
| affected_version | (`vulnerability_id`, `entry_index`, `version`) | OSV's own version list; insert-only |
| affected_release | (`canonical_name`, `version`, `vulnerability_id`, `entry_index`) | `in_range` from the PEP 440 range evaluator (`transform/ranges.py`), `in_enumerated` from OSV's version list |
| resolved_node | (root name, root version, node name, node version) | deps.dev graph; `relation` DIRECT/INDIRECT, `depth` by shortest path |

`affected_release` rows exist only where at least one of `in_range` and `in_enumerated` is known. GIT ranges (commit hashes) are stored but are not evaluated against versions.

### Load order (foreign keys)
`LOAD_ORDER` in `src/pipeline/load/tables.py`: package, release, dependency, vulnerability, vulnerability_alias, vulnerability_severity, affected_package, affected_range, affected_event, affected_version, affected_release, resolved_node, quarantine, data_quality_result (operational tables `pipeline_run` and `raw_object` go through `load/runs.py`).

### Loader interface (implemented)

```python
def load(frames: dict[str, pd.DataFrame], conn, run_id: int | None = None) -> dict[str, TableResult]: ...
# TableResult: inserted, updated, unchanged
```

Mechanics: `COPY` into a temporary staging table, parent checks (a missing parent raises `LoadError`), then `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE content_hash IS DISTINCT FROM EXCLUDED.content_hash` with `RETURNING (xmax = 0)` to count inserts. Running the same frames twice reports zero inserted and zero updated. All frames in one `load()` call are one transaction: either everything commits or nothing does. `run_id` is required for quarantine and data_quality_result. The orchestrator loads quarantine rows in their **own** `load()` call so they survive a failed data load.

`pipeline_run` status is `failed` if the run raised an exception (the exception is re-raised).

## 5. Run order (orchestrator)

`start_run` -> fetch (resumable) -> `scan_raw` and register raw objects -> validate -> load quarantine alone -> transform -> load frames -> `finish_run`.

```text
python -m pipeline.orchestrate --seed-file config/seed.txt --run-label <label>
python -m pipeline.orchestrate --packages six:A flask:B --release-limit 5   # quick test
```

## 6. Load -> Analyse

- Tables keep the blueprint names in the default schema.
- Analytical views are `v_<topic>` in `sql/views/`; SQL functions are in `sql/functions/`. They are **not** applied by the migration runner: apply them with `psql -f` after migrating (see README). Views: `v_package_release_history`, `v_package_vulnerabilities`, `v_release_dependencies`, `v_release_vulnerabilities`, `v_resolved_dependency_depth`.
- The analysis side reads only tables and views, never raw files.
- `v_resolved_dependency_depth` is **current-only** (deps.dev resolves against today's index) and must not be used as a historical feature.
- Prevalence statistics use seed tier A only.
- The dashboard is fed by `scripts/export_dashboard_data.py`, which reads the database (`DATABASE_URL`) and writes JSON to `dashboard/data/`.

## 7. Conventions

- Python 3.11 or newer (CI runs 3.12 and 3.14). Type hints on public functions.
- Config comes from `config/` and `.env`. No hard-coded paths or credentials.
- Anything that touches the network or database takes its client or connection as an argument, so tests can pass a fake.
- Fixtures live in `fixtures/<source>/`; deliberately invalid payloads in `fixtures/bad/`.
- Database tests need an **empty** database, so run them against a separate test database, never the one with real data.

## 8. Schema changes from the blueprint

1. `affected_range.range_index SMALLINT NOT NULL`, `UNIQUE (affected_id, range_index)`: done, in `001_initial_schema.sql`.
2. `package.seed_tier` allows only `'A'` or `'B'`, and `in_seed` requires a tier.

## 9. Known limits

- OSV and PyPI are live sources, so a later run can report different counts.
- `affected_version` and `vulnerability_alias` rows are insert-only: rows an advisory later drops are not deleted.
- `resolved_node` covers the releases deps.dev could resolve; graphs without a root node are quarantined.
- No `data_quality_result` rows were loaded in the reference run; the rules exist in `src/pipeline/quality/rules.py`.
