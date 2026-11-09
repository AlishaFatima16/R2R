-- Declared dependencies for each package release.
-- Includes invalid and conditional requirements for analysis.

CREATE OR REPLACE VIEW v_release_dependencies AS
SELECT
    r.release_id,
    p.package_id,
    p.canonical_name AS package_name,
    r.version,
    r.uploaded_at,
    r.deps_fetched,
    d.dependency_id,
    d.raw_requirement,
    d.requirement_valid,
    d.target_package_id,
    tp.canonical_name AS target_package_name,
    d.extras,
    d.specifier,
    d.marker,
    d.is_extra_only,
    d.is_conditional
FROM release AS r
JOIN package AS p
    ON p.package_id = r.package_id
LEFT JOIN dependency AS d
    ON d.release_id = r.release_id
LEFT JOIN package AS tp
    ON tp.package_id = d.target_package_id;