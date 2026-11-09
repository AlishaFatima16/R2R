-- Vulnerabilities linked to packages in the loaded dataset.
-- This view includes withdrawn and future advisories.
-- Use vulnerabilities_as_of() when calculating historical features.

CREATE OR REPLACE VIEW v_package_vulnerabilities AS
SELECT
    ap.affected_id,
    ap.package_id,
    ap.package_name,
    ap.entry_index,
    v.vulnerability_id,
    v.published_at,
    v.modified_at,
    v.withdrawn_at,
    v.summary,
    v.dates_out_of_order
FROM affected_package AS ap
JOIN vulnerability AS v
    ON v.vulnerability_id = ap.vulnerability_id
WHERE ap.package_id IS NOT NULL;