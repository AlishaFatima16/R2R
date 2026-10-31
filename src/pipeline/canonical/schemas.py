"""Canonical table column order shared by transforms and the database loader."""

PACKAGE_COLUMNS = (
    "canonical_name", "display_name", "in_seed", "seed_tier", "summary", "repo_url",
    "license_raw", "latest_version", "last_serial", "raw_object_id", "content_hash",
)
RELEASE_COLUMNS = (
    "canonical_name", "version", "version_valid", "version_rank", "is_prerelease",
    "is_dev", "uploaded_at", "yanked", "yanked_reason", "requires_python",
    "deps_fetched", "raw_object_id", "content_hash",
)
DEPENDENCY_COLUMNS = (
    "canonical_name", "version", "raw_requirement", "requirement_valid", "target_canonical_name",
    "extras", "specifier", "marker", "is_extra_only", "is_conditional", "content_hash",
)
VULNERABILITY_COLUMNS = (
    "vulnerability_id", "published_at", "modified_at", "withdrawn_at", "summary", "details",
    "schema_version", "dates_out_of_order", "raw_object_id", "content_hash",
)
VULNERABILITY_ALIAS_COLUMNS = ("vulnerability_id", "alias")
VULNERABILITY_SEVERITY_COLUMNS = ("vulnerability_id", "severity_type", "vector", "origin")
AFFECTED_PACKAGE_COLUMNS = ("vulnerability_id", "package_name", "package_id", "entry_index")
AFFECTED_RANGE_COLUMNS = ("vulnerability_id", "entry_index", "range_index", "range_type", "repo")
AFFECTED_EVENT_COLUMNS = (
    "vulnerability_id", "entry_index", "range_index", "event_order", "event_type", "version_string",
)
AFFECTED_VERSION_COLUMNS = ("vulnerability_id", "entry_index", "version")
