# Entity-relationship diagram

Generated from the live database schema by `scripts/generate_er_diagram.py`, so it matches `migrations/` exactly. Do not edit by hand; re-run the script.

Notation: `PK` primary key, `FK` foreign key. A relationship line reads *parent one-to-many child*; a `|o` on the parent side means the foreign key is optional (nullable).

```mermaid
erDiagram
    affected_range ||--o{ affected_event : "range_id"
    package |o--o{ affected_package : "package_id"
    vulnerability ||--o{ affected_package : "vulnerability_id"
    affected_package ||--o{ affected_range : "affected_id"
    affected_package ||--o{ affected_release : "affected_id"
    release ||--o{ affected_release : "release_id"
    affected_package ||--o{ affected_version : "affected_id"
    pipeline_run ||--o{ data_quality_result : "run_id"
    package |o--o{ dependency : "target_package_id"
    release ||--o{ dependency : "release_id"
    raw_object |o--o{ package : "raw_object_id"
    pipeline_run ||--o{ quarantine : "run_id"
    raw_object ||--o{ quarantine : "raw_object_id"
    pipeline_run ||--o{ raw_object : "run_id"
    source ||--o{ raw_object : "source_id"
    package ||--o{ release : "package_id"
    raw_object |o--o{ release : "raw_object_id"
    release ||--o{ release_external_advisory : "release_id"
    source ||--o{ release_external_advisory : "source_id"
    package ||--o{ resolved_node : "package_id"
    release ||--o{ resolved_node : "root_release_id"
    raw_object |o--o{ vulnerability : "raw_object_id"
    vulnerability ||--o{ vulnerability_alias : "vulnerability_id"
    vulnerability ||--o{ vulnerability_severity : "vulnerability_id"
    affected_event {
        bigint event_id PK
        bigint range_id FK
        smallint event_order
        text event_type
        text version_string
    }
    affected_package {
        bigint affected_id PK
        text vulnerability_id FK
        text package_name
        int package_id FK
        smallint entry_index
    }
    affected_range {
        bigint range_id PK
        bigint affected_id FK
        smallint range_index
        text range_type
        text repo
    }
    affected_release {
        bigint release_id PK, FK
        bigint affected_id PK, FK
        bool in_range
        bool in_enumerated
    }
    affected_version {
        bigint affected_id PK, FK
        text version PK
    }
    data_quality_result {
        bigint dq_id PK
        bigint run_id FK
        text check_name
        text dimension
        text table_name
        numeric metric_value
        numeric threshold
        bool passed
        jsonb details
    }
    dependency {
        bigint dependency_id PK
        bigint release_id FK
        text raw_requirement
        bool requirement_valid
        int target_package_id FK
        text_array extras
        text specifier
        text marker
        bool is_extra_only
        bool is_conditional
    }
    package {
        int package_id PK
        text canonical_name
        text display_name
        bool in_seed
        char seed_tier
        text summary
        text repo_url
        text license_raw
        text latest_version
        bigint last_serial
        bigint raw_object_id FK
        char content_hash
    }
    pipeline_run {
        bigint run_id PK
        timestamptz started_at
        timestamptz finished_at
        text status
        text git_commit
        char config_hash
        text notes
    }
    quarantine {
        bigint quarantine_id PK
        bigint run_id FK
        bigint raw_object_id FK
        text stage
        text reason_code
        text field_path
        text message
        timestamptz created_at
        timestamptz resolved_at
        text resolution
    }
    raw_object {
        bigint raw_object_id PK
        bigint run_id FK
        smallint source_id FK
        text request_url
        jsonb request_params
        smallint http_status
        timestamptz fetched_at
        char sha256
        text file_path
        int line_number
    }
    release {
        bigint release_id PK
        int package_id FK
        text version
        bool version_valid
        int version_rank
        bool is_prerelease
        bool is_dev
        timestamptz uploaded_at
        bool yanked
        text yanked_reason
        text requires_python
        bool deps_fetched
        bigint raw_object_id FK
        char content_hash
    }
    release_external_advisory {
        bigint release_id PK, FK
        smallint source_id PK, FK
        text advisory_id PK
    }
    resolved_node {
        bigint root_release_id PK, FK
        int package_id PK, FK
        text node_version PK
        text relation
        smallint depth
    }
    source {
        smallint source_id PK
        text name
        text base_url
        text docs_url
    }
    vulnerability {
        text vulnerability_id PK
        timestamptz published_at
        timestamptz modified_at
        timestamptz withdrawn_at
        text summary
        text details
        text schema_version
        bool dates_out_of_order
        bigint raw_object_id FK
        char content_hash
    }
    vulnerability_alias {
        text vulnerability_id PK, FK
        text alias PK
    }
    vulnerability_severity {
        text vulnerability_id PK, FK
        text severity_type PK
        text vector PK
        text origin
    }
```

## Tables

- **Operational (one row per run or response):** `source`, `pipeline_run`, `raw_object`, `quarantine`, `data_quality_result`
- **Packages and releases:** `package`, `release`, `dependency`, `resolved_node`, `release_external_advisory`
- **Advisories:** `vulnerability`, `vulnerability_alias`, `vulnerability_severity`, `affected_package`, `affected_range`, `affected_event`, `affected_version`, `affected_release`

Frames never carry surrogate ids: the loader resolves natural keys to the ids above (see `docs/interfaces.md`).
