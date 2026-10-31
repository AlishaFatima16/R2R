# Canonical data dictionary

Member 2 owns the validation and transformation boundary. Transforms return
Pandas frames keyed by database table name; columns are ordered as in the
migration and missing values are written as SQL `NULL`.

## PyPI

- `package.canonical_name`: lowercase PEP 503 name.
- `release.version`: published text, never rewritten.
- `release.version_valid`: whether the text parses as PEP 440.
- `release.version_rank`: ascending rank among valid releases for a package.
- `dependency.raw_requirement`: exact published requirement.
- `dependency.target_canonical_name`: normalized target, or null when parsing fails.
- `dependency.requirement_valid`, `is_extra_only`, `is_conditional`: soft validation flags.

## OSV

OSV identifiers and aliases are preserved. Package names in `affected` are
normalized. Range and event positions are retained as `entry_index`,
`range_index`, and `event_order`, making repeated runs deterministic.
`affected_release.in_range` is calculated from OSV events using PEP 440 ordering;
`in_enumerated` records OSV's explicit version list. `None` means no usable
range/list was available, not that the release is safe.

## Quarantine

Malformed records produce a `QuarantineRecord` with one of:
`missing_field`, `type_error`, `invalid_timestamp`, `malformed_identifier`,
`unexpected_structure`, `empty_body`, or `duplicate_conflict`. Records are
never silently discarded.
