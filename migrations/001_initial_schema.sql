-- 001_initial_schema.sql
-- R2R initial schema. Based on the project blueprint, Section 7.
-- Change from the blueprint (PROPOSED in docs/interfaces.md section 7):
--   affected_range.range_index added, with UNIQUE (affected_id, range_index).
-- All foreign keys are ON DELETE RESTRICT: nothing in this pipeline deletes data.

BEGIN;

-- ---------------------------------------------------------------------------
-- Operational tables
-- ---------------------------------------------------------------------------

CREATE TABLE source (
  source_id      SMALLINT PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,         -- 'pypi_json','pypi_index','osv','depsdev'
  base_url       TEXT NOT NULL,
  docs_url       TEXT
);

CREATE TABLE pipeline_run (
  run_id         BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  started_at     TIMESTAMPTZ NOT NULL,
  finished_at    TIMESTAMPTZ,
  status         TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','aborted')),
  git_commit     TEXT NOT NULL,
  config_hash    CHAR(64) NOT NULL,            -- hash of seed list + settings
  notes          TEXT
);

CREATE TABLE raw_object (
  raw_object_id  BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  run_id         BIGINT NOT NULL REFERENCES pipeline_run(run_id) ON DELETE RESTRICT,
  source_id      SMALLINT NOT NULL REFERENCES source(source_id) ON DELETE RESTRICT,
  request_url    TEXT NOT NULL,
  request_params JSONB,
  http_status    SMALLINT NOT NULL,
  fetched_at     TIMESTAMPTZ NOT NULL,
  sha256         CHAR(64) NOT NULL,
  file_path      TEXT NOT NULL,                -- data/raw/<source>/<run>/<file>.jsonl.gz
  line_number    INT NOT NULL,
  UNIQUE (source_id, request_url, sha256)      -- identical re-fetch is detected
);
CREATE INDEX ix_raw_object_run ON raw_object (run_id);

CREATE TABLE quarantine (
  quarantine_id  BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  run_id         BIGINT NOT NULL REFERENCES pipeline_run(run_id) ON DELETE RESTRICT,
  raw_object_id  BIGINT NOT NULL REFERENCES raw_object(raw_object_id) ON DELETE RESTRICT,
  stage          TEXT NOT NULL CHECK (stage IN ('validate','transform','load')),
  reason_code    TEXT NOT NULL,                -- 'missing_field','type_error',...
  field_path     TEXT,
  message        TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at    TIMESTAMPTZ,                  -- set when reprocessed after a fix
  resolution     TEXT
);
CREATE INDEX ix_quarantine_run_reason ON quarantine (run_id, reason_code);
CREATE INDEX ix_quarantine_raw_object ON quarantine (raw_object_id);

CREATE TABLE data_quality_result (
  dq_id          BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  run_id         BIGINT NOT NULL REFERENCES pipeline_run(run_id) ON DELETE RESTRICT,
  check_name     TEXT NOT NULL,
  dimension      TEXT NOT NULL CHECK (dimension IN ('completeness','validity','uniqueness',
                   'consistency','referential_integrity','freshness','source_agreement')),
  table_name     TEXT,
  metric_value   NUMERIC NOT NULL,
  threshold      NUMERIC,
  passed         BOOLEAN NOT NULL,
  details        JSONB,
  UNIQUE (run_id, check_name, table_name)
);

-- ---------------------------------------------------------------------------
-- Package, release and dependency
-- ---------------------------------------------------------------------------

CREATE TABLE package (
  package_id     INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  canonical_name TEXT NOT NULL UNIQUE CHECK (canonical_name = lower(canonical_name)),
  display_name   TEXT,                         -- name as published
  in_seed        BOOLEAN NOT NULL DEFAULT false,
  seed_tier      CHAR(1) CHECK (seed_tier IN ('A','B')),
  summary        TEXT,
  repo_url       TEXT,
  license_raw    TEXT,
  latest_version TEXT,
  last_serial    BIGINT,
  raw_object_id  BIGINT REFERENCES raw_object(raw_object_id) ON DELETE RESTRICT,
  content_hash   CHAR(64) NOT NULL,
  CHECK ((seed_tier IS NULL) = (NOT in_seed))
);

CREATE TABLE release (
  release_id     BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  package_id     INT NOT NULL REFERENCES package(package_id) ON DELETE RESTRICT,
  version        TEXT NOT NULL,
  version_valid  BOOLEAN NOT NULL,             -- valid PEP 440
  version_rank   INT,                          -- order within package; NULL if invalid
  is_prerelease  BOOLEAN NOT NULL,
  is_dev         BOOLEAN NOT NULL,
  uploaded_at    TIMESTAMPTZ,                  -- earliest file upload time
  yanked         BOOLEAN NOT NULL,
  yanked_reason  TEXT,
  requires_python TEXT,
  deps_fetched   BOOLEAN NOT NULL,             -- per-release JSON was read
  raw_object_id  BIGINT REFERENCES raw_object(raw_object_id) ON DELETE RESTRICT,
  content_hash   CHAR(64) NOT NULL,
  UNIQUE (package_id, version),
  CHECK (version_valid OR version_rank IS NULL)
);
CREATE INDEX ix_release_uploaded_at ON release (uploaded_at);

CREATE TABLE dependency (
  dependency_id  BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  release_id     BIGINT NOT NULL REFERENCES release(release_id) ON DELETE RESTRICT,
  raw_requirement TEXT NOT NULL,               -- exactly as published
  requirement_valid BOOLEAN NOT NULL,
  target_package_id INT REFERENCES package(package_id) ON DELETE RESTRICT,  -- NULL if requirement_valid is false
  extras         TEXT[],
  specifier      TEXT,                         -- e.g. '>=2.0,<3'
  marker         TEXT,
  is_extra_only  BOOLEAN NOT NULL,
  is_conditional BOOLEAN NOT NULL,
  UNIQUE (release_id, raw_requirement),
  CHECK (NOT requirement_valid OR target_package_id IS NOT NULL)
);
CREATE INDEX ix_dependency_target ON dependency (target_package_id);

-- ---------------------------------------------------------------------------
-- Vulnerability tables
-- ---------------------------------------------------------------------------

CREATE TABLE vulnerability (
  vulnerability_id TEXT PRIMARY KEY,           -- OSV id, e.g. 'PYSEC-2021-9'
  published_at   TIMESTAMPTZ,
  modified_at    TIMESTAMPTZ NOT NULL,
  withdrawn_at   TIMESTAMPTZ,
  summary        TEXT,
  details        TEXT,
  schema_version TEXT,
  dates_out_of_order BOOLEAN NOT NULL,         -- soft flag from validation
  raw_object_id  BIGINT REFERENCES raw_object(raw_object_id) ON DELETE RESTRICT,
  content_hash   CHAR(64) NOT NULL
);

CREATE TABLE vulnerability_alias (
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(vulnerability_id) ON DELETE RESTRICT,
  alias          TEXT NOT NULL,
  PRIMARY KEY (vulnerability_id, alias)
);
CREATE INDEX ix_vulnerability_alias_alias ON vulnerability_alias (alias);

CREATE TABLE vulnerability_severity (
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(vulnerability_id) ON DELETE RESTRICT,
  severity_type  TEXT NOT NULL,                -- 'CVSS_V3', 'CVSS_V4', ...
  vector         TEXT NOT NULL,
  origin         TEXT,                         -- OSV 'source' field
  PRIMARY KEY (vulnerability_id, severity_type, vector)
);

CREATE TABLE affected_package (
  affected_id    BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(vulnerability_id) ON DELETE RESTRICT,
  package_name   TEXT NOT NULL,                -- normalized
  package_id     INT REFERENCES package(package_id) ON DELETE RESTRICT,  -- NULL if outside the loaded set
  entry_index    SMALLINT NOT NULL,            -- position in OSV 'affected'
  UNIQUE (vulnerability_id, entry_index)
);
CREATE INDEX ix_affected_package_package ON affected_package (package_id);

CREATE TABLE affected_range (
  range_id       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  affected_id    BIGINT NOT NULL REFERENCES affected_package(affected_id) ON DELETE RESTRICT,
  range_index    SMALLINT NOT NULL,            -- position in OSV 'ranges' (PROPOSED addition)
  range_type     TEXT NOT NULL CHECK (range_type IN ('SEMVER','ECOSYSTEM','GIT')),
  repo           TEXT,
  UNIQUE (affected_id, range_index),
  CHECK (range_type <> 'GIT' OR repo IS NOT NULL)
);

CREATE TABLE affected_event (
  event_id       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  range_id       BIGINT NOT NULL REFERENCES affected_range(range_id) ON DELETE RESTRICT,
  event_order    SMALLINT NOT NULL,
  event_type     TEXT NOT NULL CHECK (event_type IN ('introduced','fixed','last_affected','limit')),
  version_string TEXT NOT NULL,
  UNIQUE (range_id, event_order)
);

CREATE TABLE affected_version (
  affected_id    BIGINT NOT NULL REFERENCES affected_package(affected_id) ON DELETE RESTRICT,
  version        TEXT NOT NULL,
  PRIMARY KEY (affected_id, version)
);

CREATE TABLE affected_release (
  release_id     BIGINT NOT NULL REFERENCES release(release_id) ON DELETE RESTRICT,
  affected_id    BIGINT NOT NULL REFERENCES affected_package(affected_id) ON DELETE RESTRICT,
  in_range       BOOLEAN,                      -- our range evaluation (NULL if no usable range)
  in_enumerated  BOOLEAN,                      -- OSV's version list (NULL if list empty)
  PRIMARY KEY (release_id, affected_id),
  CHECK (in_range IS NOT NULL OR in_enumerated IS NOT NULL)
);
CREATE INDEX ix_affected_release_affected ON affected_release (affected_id);

-- ---------------------------------------------------------------------------
-- Cross-source and graph tables
-- ---------------------------------------------------------------------------

CREATE TABLE release_external_advisory (
  release_id     BIGINT NOT NULL REFERENCES release(release_id) ON DELETE RESTRICT,
  source_id      SMALLINT NOT NULL REFERENCES source(source_id) ON DELETE RESTRICT,  -- pypi_json or depsdev
  advisory_id    TEXT NOT NULL,
  PRIMARY KEY (release_id, source_id, advisory_id)
);

CREATE TABLE resolved_node (
  root_release_id BIGINT NOT NULL REFERENCES release(release_id) ON DELETE RESTRICT,
  package_id     INT NOT NULL REFERENCES package(package_id) ON DELETE RESTRICT,
  node_version   TEXT NOT NULL,
  relation       TEXT NOT NULL CHECK (relation IN ('DIRECT','INDIRECT')),
  depth          SMALLINT NOT NULL CHECK (depth >= 1),  -- hops from root, computed from edges
  PRIMARY KEY (root_release_id, package_id, node_version)
);

-- ---------------------------------------------------------------------------
-- Reference data
-- ---------------------------------------------------------------------------

INSERT INTO source (source_id, name, base_url, docs_url) VALUES
  (1, 'pypi_json',  'https://pypi.org/pypi',   'https://docs.pypi.org/api/json/'),
  (2, 'pypi_index', 'https://pypi.org/simple', 'https://docs.pypi.org/api/index-api/'),
  (3, 'osv',        'https://api.osv.dev',     'https://google.github.io/osv.dev/api/'),
  (4, 'depsdev',    'https://api.deps.dev',    'https://docs.deps.dev/api/v3/')
ON CONFLICT (source_id) DO NOTHING;

COMMIT;