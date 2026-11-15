# R2R Risk Observatory (dashboard)

A static, no-build-step dashboard for the R2R pipeline: live PyPI and OSV data, through raw files,
Pydantic validation and pandas into PostgreSQL, through the SQL views in `sql/views/`, to this site.

It is plain HTML, CSS and ES modules with hand-drawn SVG charts. There are no CDN scripts, no
npm packages and no tracking; the two fonts (Geist, Geist Mono, SIL OFL) are self-hosted in
`assets/fonts/`. Every path is relative, so it works from any sub-folder (GitHub Pages, Netlify).

Pages: Overview, Packages (explorer), Package (release timeline strip), Advisories, Advisory, Pipeline.

## Prevalence statistics use tier A only

Tier A is the 80 most downloaded packages. Tier B is 40 extra packages picked *because* they have
many advisories, so including them would overstate how common vulnerabilities are. Every
prevalence number (advisories, share of releases affected, time to fix) is computed from tier A
and says so on the page. Tier B stays visible in the explorer and on its own package pages.

## What is in this folder

| Path | What it is |
|---|---|
| `index.html`, `assets/` | the site (hash routing: `#/`, `#/packages`, `#/package/<name>`, `#/advisories`, `#/advisory/<id>`, `#/pipeline`) |
| `data/overview.json` | headline numbers and the four overview charts; `is_sample` flag |
| `data/packages.json` | one row per seed package, for the explorer |
| `data/packages/<name>.json` | one file per package: releases, advisory windows, dependencies (lazy loaded) |
| `data/advisories.json` | one row per advisory record, for search and the advisory page |
| `data/pipeline.json` | latest run: stage counts, quarantine by reason code, data quality, run history |

Every JSON file carries `generated_at`, `run_id` and `is_sample`.

## Sample data first, real data after

`data/` ships with **sample data** built from the saved responses in `fixtures/` (six, flask,
requests, django, pillow, pyyaml, urllib3, jinja2), run through the repository's own validate and
transform code. While `overview.json` has `"is_sample": true`, a black "SAMPLE DATA" banner is shown
and numbers carry a "sample" tag. The real export sets the flag to `false` and the banner
disappears. Rebuild the sample at any time (no database, no network):

```powershell
python scripts/build_sample_dashboard_data.py
```

## Export real data

The exporter only reads. It takes the connection string from the `DATABASE_URL` environment
variable (or a local `.env`), never from a flag, and never writes it anywhere.

```powershell
$env:DATABASE_URL = "postgresql://r2r:<password>@localhost:5432/r2r"
python scripts/export_dashboard_data.py
```

```bash
export DATABASE_URL=postgresql://r2r:<password>@localhost:5432/r2r
python scripts/export_dashboard_data.py
```

Options: `--out dashboard/data` (default), `--as-of 2026-11-15T00:00:00Z` (use a fixed "now"),
`--repo-url https://github.com/<owner>/<repo>` (or set `R2R_REPO_URL`). It prints the number of
files and the total size, and warns if the site would exceed 5 MB. Files in `data/packages/` from
an earlier export are replaced.

What it queries: `v_package_release_history`, `v_package_vulnerabilities`, `v_release_vulnerabilities`,
`v_release_dependencies`, `v_resolved_dependency_depth`, and the point-in-time function
`vulnerabilities_as_of(now)` (so withdrawn and unpublished advisories are left out; the count of
those is shown on the Overview). It also reads a few base tables the views do not expose:
`package`, `vulnerability_alias`, `vulnerability_severity`, `affected_*` (range events),
`pipeline_run`, `raw_object`, `quarantine`, `data_quality_result`.

### How the numbers are defined

- **Advisories** are merged when records share an alias: a GHSA and a PYSEC record for the same CVE
  count once. The raw record count is shown next to it.
- **Affected release**: inside an OSV affected range, as evaluated by the pipeline
  (`affected_release.in_range`, falling back to OSV's enumerated list when no range is usable).
- **Severity**: the CVSS v3 base score computed from the advisory's vector. Advisories with no v3
  vector (including CVSS v4 only) are shown as *unrated*, never guessed.
- **Exposure window**: from the upload date of the introduced release to the upload date of the
  fixed release. `introduced: 0` means "since the first release": it is drawn, but left out of
  time-to-fix because the real start is unknown. Windows with no fix are drawn hatched and run to
  the export time.
- **Dependencies**: the resolved graph from deps.dev (with depth) when loaded, otherwise the
  direct requirements of the latest release.

## Preview

```powershell
cd dashboard
python -m http.server 8000
```

Open <http://localhost:8000>. Opening `index.html` straight from disk does not work, because
browsers block `fetch()` on `file://`; the page says so if it happens. Keyboard: `/` or `Ctrl+K`
focuses search; the theme button switches light and dark (the default follows the system).

## Deploy to GitHub Pages

1. **Let git track `dashboard/data/`.** The repository's `.gitignore` contains `data/`, which also
   matches `dashboard/data/`. Add this line *after* it in `.gitignore`:

   ```
   !dashboard/data/
   ```

   (or run `git add -f dashboard/data` once; new package files later would need `-f` again).
2. Run the export (or keep the sample), then commit `dashboard/` and push to `main`.
3. In the repository: **Settings, Pages, Build and deployment, Source: GitHub Actions**.
4. `.github/workflows/pages.yml` publishes `dashboard/` on every push to `main` that touches it,
   after checking that the JSON parses, contains no connection string and the site is under 5 MB.

Netlify or any static host: publish the `dashboard/` folder, no build command.

To refresh the live site: run the export, commit `dashboard/data/`, push.

## Tests

`tests/unit/test_export_dashboard.py` runs without a database (plain rows and a stub connection)
and also builds the sample from `fixtures/`:

```powershell
python -m pytest tests/unit/test_export_dashboard.py -q
python -m ruff check src tests
```
