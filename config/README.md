# Seed list methodology

## Tier A: download popularity

The download snapshot was obtained on 2026-11-01 from:

https://raw.githubusercontent.com/hugovk/top-pypi-packages/2026.08/top-pypi-packages-30-days.csv

Tier A contains the top 80 packages by download count in that snapshot. OSV advisory counts are not used to select Tier A.

## Tier B: OSV advisory counts

OSV counts were collected for packages ranked 81 through 700 in the download snapshot. The M1 extractor was run in two batches using:

```powershell
python -m pipeline.extract.cli --packages-file <candidate-file> --sources osv --run-label <run-label> --root <project-root>
```

The runs used the labels `tierb-count` and `tierb-extra`. The resulting compressed JSONL files were read to count distinct OSV vulnerability IDs (`vuln.id`) per package. Tier A packages were excluded from the candidates.

Tier B contains the 40 remaining packages with the highest distinct OSV advisory counts. Packages were sorted by descending advisory count, then alphabetically by package name to break ties.

At 10 advisories, `flask`, `httpx2`, and `joserfc` were included; `mako`, `poetry`, `pyopenssl`, and `weasyprint` were excluded.

## Seed file format

`seed.txt` contains one package per line in `name,tier` format. Lines beginning with `#` are comments and are ignored.