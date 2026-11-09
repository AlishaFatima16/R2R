-- Current resolved dependency graph from deps.dev.
-- CURRENT-ONLY: this data must not be used as a historical feature.

CREATE OR REPLACE VIEW v_resolved_dependency_depth AS
SELECT
    rn.root_release_id,
    root_package.canonical_name AS root_package_name,
    root_release.version AS root_version,
    rn.package_id AS dependency_package_id,
    dependency_package.canonical_name AS dependency_package_name,
    rn.node_version,
    rn.relation,
    rn.depth
FROM resolved_node AS rn
JOIN release AS root_release
    ON root_release.release_id = rn.root_release_id
JOIN package AS root_package
    ON root_package.package_id = root_release.package_id
JOIN package AS dependency_package
    ON dependency_package.package_id = rn.package_id;