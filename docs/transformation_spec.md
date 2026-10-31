# Transformation specification

`transform_pypi_project` and `transform_osv` accept decoded fixture/API
payloads and never perform network or database operations. Each returns
`(frames, quarantine)`; validation failures return no partial frame and a
quarantine record.

Package names use `packaging.utils.canonicalize_name`. Version text is
preserved, while `packaging.version.Version` supplies validity and ordering.
Requirements are parsed with `packaging.requirements.Requirement`; invalid
requirements stay in the dependency frame with `requirement_valid=False`.

OSV ranges are evaluated as half-open intervals (`introduced <= version <
fixed`), with `last_affected` inclusive. Multiple ranges are ORed. A malformed
version or unusable range returns null, allowing quality reporting without
claiming a false safe result.
