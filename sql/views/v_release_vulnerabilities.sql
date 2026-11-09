-- Links individual releases to vulnerability assessments.
-- These are stored assessments, not historical point-in-time results.

CREATE OR REPLACE VIEW v_release_vulnerabilities AS
SELECT
    r.release_id,
    p.package_id,
    p.canonical_name,
    r.version,
    r.uploaded_at,
    v.vulnerability_id,
    v.published_at,
    v.withdrawn_at,
    ar.in_range,
    ar.in_enumerated
FROM affected_release AS ar
JOIN release AS r
    ON r.release_id = ar.release_id
JOIN package AS p
    ON p.package_id = r.package_id
JOIN affected_package AS ap
    ON ap.affected_id = ar.affected_id
JOIN vulnerability AS v
    ON v.vulnerability_id = ap.vulnerability_id;