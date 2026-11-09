-- Return only releases that were available on or before the requested date.
-- Releases with an unknown upload date are excluded.

CREATE OR REPLACE FUNCTION releases_as_of(p_as_of TIMESTAMPTZ)
RETURNS SETOF release
LANGUAGE sql
STABLE
AS $$
    SELECT r.*
    FROM release AS r
    WHERE r.uploaded_at IS NOT NULL
      AND r.uploaded_at <= p_as_of;
$$;
-- Return advisories published by the requested date
-- and not withdrawn on or before that date.

CREATE OR REPLACE FUNCTION vulnerabilities_as_of(p_as_of TIMESTAMPTZ)
RETURNS SETOF vulnerability
LANGUAGE sql
STABLE
AS $$
    SELECT v.*
    FROM vulnerability AS v
    WHERE v.published_at IS NOT NULL
      AND v.published_at <= p_as_of
      AND (
          v.withdrawn_at IS NULL
          OR v.withdrawn_at > p_as_of
      );
$$;
-- Calculate declared dependency counts using the latest release
-- available for each package on the requested date.
-- Missing dependency data remains NULL, not zero.

CREATE OR REPLACE FUNCTION dependency_counts_as_of(p_as_of TIMESTAMPTZ)
RETURNS TABLE (
    package_id INT,
    canonical_name TEXT,
    release_id BIGINT,
    version TEXT,
    dependency_count BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH latest_release AS (
        SELECT DISTINCT ON (r.package_id)
            r.package_id,
            r.release_id,
            r.version,
            r.deps_fetched
        FROM releases_as_of(p_as_of) AS r
        ORDER BY r.package_id, r.uploaded_at DESC, r.release_id DESC
    ),
    dependency_counts AS (
        SELECT
            lr.release_id,
            COUNT(DISTINCT d.target_package_id) FILTER (
                WHERE d.requirement_valid
                  AND d.target_package_id IS NOT NULL
                  AND NOT d.is_extra_only
            ) AS dependency_count
        FROM latest_release AS lr
        LEFT JOIN dependency AS d
            ON d.release_id = lr.release_id
        GROUP BY lr.release_id
    )
    SELECT
        p.package_id,
        p.canonical_name,
        lr.release_id,
        lr.version,
        CASE
            WHEN lr.release_id IS NULL OR NOT lr.deps_fetched THEN NULL
            ELSE COALESCE(dc.dependency_count, 0)
        END AS dependency_count
    FROM package AS p
    LEFT JOIN latest_release AS lr
        ON lr.package_id = p.package_id
    LEFT JOIN dependency_counts AS dc
        ON dc.release_id = lr.release_id;
$$;
-- Count non-yanked releases in the 365 days before the requested date.

CREATE OR REPLACE FUNCTION release_frequency_as_of(p_as_of TIMESTAMPTZ)
RETURNS TABLE (
    package_id INT,
    canonical_name TEXT,
    release_frequency BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        p.package_id,
        p.canonical_name,
        COUNT(r.release_id) AS release_frequency
    FROM package AS p
    LEFT JOIN releases_as_of(p_as_of) AS r
        ON r.package_id = p.package_id
        AND r.uploaded_at > p_as_of - INTERVAL '365 days'
        AND NOT r.yanked
    GROUP BY p.package_id, p.canonical_name;
$$;
-- Calculate package age and release recency as of a requested date.

CREATE OR REPLACE FUNCTION package_lifecycle_as_of(p_as_of TIMESTAMPTZ)
RETURNS TABLE (
    package_id INT,
    canonical_name TEXT,
    package_age_days BIGINT,
    release_recency_days BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        p.package_id,
        p.canonical_name,
        CASE
            WHEN MIN(r.uploaded_at) IS NULL THEN NULL
            ELSE FLOOR(
                EXTRACT(EPOCH FROM (p_as_of - MIN(r.uploaded_at))) / 86400
            )::BIGINT
        END AS package_age_days,
        CASE
            WHEN MAX(r.uploaded_at) IS NULL THEN NULL
            ELSE FLOOR(
                EXTRACT(EPOCH FROM (p_as_of - MAX(r.uploaded_at))) / 86400
            )::BIGINT
        END AS release_recency_days
    FROM package AS p
    LEFT JOIN releases_as_of(p_as_of) AS r
        ON r.package_id = p.package_id
    GROUP BY p.package_id, p.canonical_name;
$$;
CREATE OR REPLACE FUNCTION metadata_completeness()
RETURNS TABLE (
    package_id INT,
    canonical_name TEXT,
    metadata_completeness NUMERIC
)
LANGUAGE sql
STABLE
AS $$
    WITH latest_release AS (
        SELECT DISTINCT ON (package_id)
            package_id,
            requires_python
        FROM release
        ORDER BY package_id, uploaded_at DESC NULLS LAST, release_id DESC
    )
    SELECT
        p.package_id,
        p.canonical_name,
        (
            (
                (p.repo_url IS NOT NULL)::INT +
                (p.license_raw IS NOT NULL)::INT +
                (p.summary IS NOT NULL)::INT +
                (lr.requires_python IS NOT NULL)::INT
            ) / 4.0
        ) AS metadata_completeness
    FROM package AS p
    LEFT JOIN latest_release AS lr
        ON lr.package_id = p.package_id;
$$;
-- Count distinct vulnerability alias groups affecting a package.
-- Only advisories published by the requested date are included.
-- Advisories withdrawn on or before that date are excluded.

CREATE OR REPLACE FUNCTION vulnerability_counts_as_of(
    p_as_of TIMESTAMPTZ
)
RETURNS TABLE (
    package_id INTEGER,
    canonical_name TEXT,
    vulnerability_count BIGINT,
    historical_vulnerability_count BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH eligible_vulnerabilities AS (
        SELECT
            v.vulnerability_id,
            COALESCE(
                MIN(va.alias),
                v.vulnerability_id
            ) AS alias_group,
            v.published_at
        FROM vulnerability AS v
        LEFT JOIN vulnerability_alias AS va
            ON va.vulnerability_id = v.vulnerability_id
        WHERE v.published_at IS NOT NULL
          AND v.published_at <= p_as_of
          AND (
              v.withdrawn_at IS NULL
              OR v.withdrawn_at > p_as_of
          )
        GROUP BY v.vulnerability_id, v.published_at
    ),
    package_vulnerabilities AS (
        SELECT DISTINCT
            ap.package_id,
            ev.alias_group,
            ev.published_at
        FROM affected_package AS ap
        JOIN eligible_vulnerabilities AS ev
            ON ev.vulnerability_id = ap.vulnerability_id
        WHERE ap.package_id IS NOT NULL
    )
    SELECT
        p.package_id,
        p.canonical_name,
        COUNT(DISTINCT pv.alias_group) AS vulnerability_count,
        COUNT(DISTINCT pv.alias_group) FILTER (
            WHERE pv.published_at > p_as_of - INTERVAL '730 days'
        ) AS historical_vulnerability_count
    FROM package AS p
    LEFT JOIN package_vulnerabilities AS pv
        ON pv.package_id = p.package_id
    GROUP BY p.package_id, p.canonical_name;
$$;