# Interfaces between pipeline stages

Owner: M3 (drafts). All four members must agree before this is treated as final.
Status: DRAFT v0.1. Change it only by pull request, and tag the affected owner.

This file defines what each stage hands to the next, so that everyone can build in parallel against fixtures. The table definitions come from the project blueprint (Section 7). Anything marked PROPOSED is a change or addition that the team has not yet agreed.

## 1. Stages and owners

| Stage | Owner | Input | Output |
|---|---|---|---|
| Extract | M1 | seed list, config | raw files + `raw_object` manifest rows |
| Validate | M2 | raw responses | valid records, quarantine records |
| Transform | M2 | valid records | one DataFrame per table (see section 4) |
| Load | M3 | DataFrames, quarantine rows | PostgreSQL tables, `data_quality_result` rows |
| Analyse | M4 | database views | EDA, quality report, feature table |

Rules for every stage:
- No stage calls the network except Extract.
- Every stage can be run from saved fixtures, with no database or API needed (except Load, which needs PostgreSQL).
- A stage never deletes data. Hard failures go to quarantine and soft problems get a boolean flag.

## 2. Extract -> Validate (M1 to M2)

### Raw files
Path: `data/raw/<source>/<run_id>/<name>.jsonl.gz` (the `data/` folder is never committed).
One line per HTTP response, as JSON:

```json
{"request_url": "...", "request_params": {}, "http_status": 200,
 "fetched_at": "2026-10-15T10:30:00Z", "body": { }}
```

`sha256` is computed over the response bytes as received and is stored in the manifest, not in the line.
Each response also gets one `raw_object` row (columns as in the blueprint: run_id, source_id, request_url, request_params, http_status, fetched_at, sha256, file_path, line_number). Identical re-fetches are detected by the unique key (source_id, request_url, sha256).

### Python interface (PROPOSED)

```python
@dataclass(frozen=True)
class RawResponse:
    source: str                 # 'pypi_json' | 'pypi_index' | 'osv' | 'depsdev'
    request_url: str
    request_params: dict | None
    http_status: int
    fetched_at: datetime        # timezone-aware, UTC
    raw_object_id: int | None   # None when reading fixtures
    body: Any                   # parsed JSON

def iter_raw(source: str, run_id: int | None = None) -> Iterator[RawResponse]: ...
```

`iter_raw` reads from the raw files (or from `fixtures/`), never from the network. M1 owns it. M2 builds against it.

## 3. Validate -> Transform (M2, internal) and quarantine

Pydantic contracts live in `src/pipeline/contracts/`. A response either validates or produces a quarantine record:

```python
@dataclass
class QuarantineRecord:
    raw_object_id: int | None
    stage: str          # 'validate' | 'transform' | 'load'
    reason_code: str
    field_path: str | None
    message: str | None
```

Initial reason codes (M2 owns this list): `missing_field`, `type_error`, `invalid_timestamp`, `malformed_identifier`, `unexpected_structure`, `empty_body`, `duplicate_conflict`.

Soft problems do not quarantine. They are flags on the row: `version_valid`, `requirement_valid`, `dates_out_of_order`, `is_conditional`, `is_extra_only`.

## 4. Transform -> Load (M2 to M3)

Transform returns `dict[str, pandas.DataFrame]`, keyed by table name. Each DataFrame has exactly the columns of that table, in the order of the migration, minus surrogate keys.

Key rules:
- **M2 does not assign surrogate IDs.** Frames carry natural keys. The loader looks up or creates `package_id`, `release_id` and so on. This keeps the stages independent.
- All timestamps are timezone-aware UTC.
- Package names are normalised (PEP 503) and lowercase.
- Versions are kept as text exactly as published, with `version_valid` and `version_rank` computed by M2.
- `content_hash` (SHA-256 hex, 64 chars) is computed by M2 over the row's mutable business columns, in a fixed column order. The loader uses it to skip unchanged rows.
- Missing values are `None` (null), never an empty string.

### Natural keys by table

| Table | Natural key in the frame | Notes |
|---|---|---|
| source | `name` | seeded by migration |
| pipeline_run | (created by loader) | M3 |
| raw_object | (source, request_url, sha256) | written by M1's raw writer |
| quarantine | (none; append-only) | linked by `raw_object_id` |
| data_quality_result | (run_id, check_name, table_name) | M2 rules, M3 writes |
| package | `canonical_name` | includes neighbour packages that dependencies point to |
| release | (`canonical_name`, `version`) | |
| dependency | (`canonical_name`, `version`, `raw_requirement`) | also carries `target_canonical_name` (null if requirement invalid) |
| vulnerability | `vulnerability_id` | |
| vulnerability_alias | (`vulnerability_id`, `alias`) | |
| vulnerability_severity | (`vulnerability_id`, `severity_type`, `vector`) | |
| affected_package | (`vulnerability_id`, `entry_index`) | carries `package_name`; loader resolves `package_id` |
| affected_range | (`vulnerability_id`, `entry_index`, `range_index`) | `range_index` is PROPOSED, see section 7 |
| affected_event | (`vulnerability_id`, `entry_index`, `range_index`, `event_order`) | |
| affected_release | (`canonical_name`, `version`, `vulnerability_id`, `entry_index`) | M2's range evaluator output |
| affected_version | (`vulnerability_id`, `entry_index`, `version`) | stretch tier |
| release_external_advisory | (`canonical_name`, `version`, source, `advisory_id`) | stretch tier |
| resolved_node | (root `canonical_name`, root `version`, node `canonical_name`, `node_version`) | stretch tier, M4 |

### Load order (foreign keys)
source -> pipeline_run -> raw_object -> package -> release -> dependency -> vulnerability -> alias, severity -> affected_package -> affected_range -> affected_event -> affected_release -> quarantine -> data_quality_result.

### Loader interface (PROPOSED)

```python
def load(frames: dict[str, pd.DataFrame], run_id: int, conn) -> LoadResult: ...
# LoadResult: per table -> inserted, updated, unchanged, rejected
```

Mechanics (M3): `COPY` into a staging table, then `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE content_hash IS DISTINCT FROM EXCLUDED.content_hash`. Running the same frames twice must report zero inserted and zero updated. If a gate check fails, nothing is committed and the run is marked `aborted`.

## 5. Load -> Analyse (M3 to M4)

- Tables keep the blueprint names, in the default schema.
- Analytical views are named `v_<topic>`. Derived tables and marts are named `mart_<topic>`. The SQL lives in `sql/views/` and `sql/marts/` (M4).
- M4 reads only from tables and views. It never reads raw files.
- Prevalence statistics use seed tier A only (see the blueprint's EDA rules).

## 6. Conventions

- Python 3.11 or newer. Type hints on all public functions.
- Config comes from `config/` and `.env`. No hard-coded paths or credentials.
- Every function that touches the network or the database takes its client or connection as an argument, so tests can pass a fake.
- Fixtures live in `fixtures/<source>/`. Deliberately invalid payloads go in `fixtures/bad/`, one per reason code.

## 7. Proposed changes to the blueprint schema

1. Add `range_index SMALLINT NOT NULL` to `affected_range`, with `UNIQUE (affected_id, range_index)`. Without it the loader has no natural key for ranges.

## 8. Open decisions

- **Scope tiers:** the blueprint assumes 7 weeks. If the deadline is 2 weeks, the stretch-tier tables (`affected_version`, `release_external_advisory`, `resolved_node`) are loaded last or dropped. To be confirmed.
- **HTTP library:** `requests` is the current default in `pyproject.toml`. M1 to confirm.
- **Python version:** the project requires 3.11 or newer. The team should agree on one version for everyone.