-- Package and release history.
-- This view exposes stored release history; it is not itself
-- a point-in-time feature dataset.
-- Use releases_as_of() for historical release cutoffs.

CREATE OR REPLACE VIEW v_package_release_history AS
SELECT
    p.package_id,
    p.canonical_name,
    p.display_name,
    p.in_seed,
    p.seed_tier,
    r.release_id,
    r.version,
    r.version_valid,
    r.version_rank,
    r.is_prerelease,
    r.is_dev,
    r.uploaded_at,
    r.yanked,
    r.requires_python,
    r.deps_fetched
FROM package AS p
LEFT JOIN release AS r
    ON r.package_id = p.package_id;