import { getJSON, h, fmt, panel, responsive, sampleTag, tierATag, errorState } from "../lib.js";
import { advisoriesByYear, affectedByYear, fixHistogram, topPackages } from "../charts.js";

function stat(label, value, sub, { tierA = false, sample = false } = {}) {
  return h("div", { class: "stat" },
    h("div", { class: "stat-label" }, label, tierA ? tierATag() : null),
    h("div", { class: "stat-value" }, value, sample ? h("span", { class: "stat-flag" }, sampleTag()) : null),
    h("div", { class: "stat-sub" }, sub));
}

function chart(draw) {
  const host = h("div", { class: "chart" });
  responsive(host, draw);
  return host;
}

export function overview(ctx) {
  const stats = h("div", { class: "stats", "aria-label": "Headline numbers" },
    Array.from({ length: 5 }, () => h("div", { class: "stat" }, h("div", { class: "sk sk-line", style: "width:60%" }), h("div", { class: "sk", style: "height:30px;width:50%;margin:8px 0" }), h("div", { class: "sk sk-line", style: "width:80%" }))));
  const meta = h("p", { class: "meta-line" });
  const notes = h("div", { class: "notes" });

  const data = getJSON("overview.json");
  data.then((d) => {
    const hl = d.headline;
    const sample = Boolean(d.is_sample);
    ctx.setBanner(d.is_sample);
    meta.textContent = `Generated ${fmt.dateTime(d.generated_at)}${d.run_id != null ? ` · pipeline run #${d.run_id}` : ""}`;
    stats.replaceChildren(
      stat("Packages tracked", fmt.int(hl.packages), `${fmt.int(hl.packages_tier_a)} tier A · ${fmt.int(hl.packages_tier_b)} tier B`, { sample }),
      stat("Releases", fmt.int(hl.releases), `${fmt.int(hl.releases_tier_a)} of them in tier A`, { sample }),
      stat("Advisories", fmt.int(hl.advisories), `${fmt.int(hl.advisory_records)} records, merged where they share a CVE, GHSA or PYSEC alias`, { tierA: true, sample }),
      stat("Releases affected", hl.share_affected == null ? "n/a" : fmt.pct(hl.share_affected, 1),
        `${fmt.int(hl.affected_releases)} of ${fmt.int(hl.releases_tier_a)} fall in the affected range of at least one advisory`, { tierA: true, sample }),
      stat("Median time to fix", hl.median_fix_days == null ? "n/a" : h("span", null, fmt.int(Math.round(hl.median_fix_days)), h("small", null, "days")),
        `introduced release to fixed release, ${fmt.int(hl.fix_windows)} closed windows`, { tierA: true, sample }));
    notes.replaceChildren(...[
      h("p", null, h("b", null, "How to read this. "), "Prevalence numbers use tier A only: the most downloaded packages. Tier B packages were added because they have many advisories, so including them would overstate how common vulnerabilities are. They stay visible in the explorer."),
      h("p", null, h("b", null, "Affected "), "means a release falls inside an OSV affected range, evaluated against PEP 440 versions. ", h("b", null, "Severity "), "is the CVSS v3 base score computed from each advisory's vector; advisories without a v3 vector are shown as unrated. ",
        h("b", null, "Time to fix "), "counts only windows whose introduced and fixed releases both have upload dates; windows that start at the package's first release are left out because their real start is unknown."),
      d.headline.excluded_advisories ? h("p", null, `${fmt.int(d.headline.excluded_advisories)} advisories were left out because they are withdrawn or have no publication date.`) : null,
    ].filter(Boolean));
  }).catch((err) => stats.replaceChildren(errorState(err, "the overview numbers")));

  const aside = (text) => h("span", { class: "meta-line" }, text);
  const body = (fn) => async () => fn(await data);

  return h("div", { class: "view" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Overview"), h("p", { class: "lede" }, "How exposed the PyPI ecosystem is to published vulnerabilities, from live PyPI and OSV data.")), meta),
    stats,
    h("div", { class: "grid-2" },
      panel({ title: "Advisories published per year", sub: "Unique advisories affecting tier A packages, by severity", aside: aside("tier A only") },
        body((d) => chart((w) => advisoriesByYear(w, d.advisories_by_year)))),
      panel({ title: "Releases affected, by release year", sub: "Share of releases published that year inside an affected range", aside: aside("tier A only") },
        body((d) => chart((w) => affectedByYear(w, d.affected_by_year)))),
      panel({ title: "How long fixes took", sub: "Days from the introduced release to the fixed release", aside: aside("tier A only") },
        body((d) => h("div", null, chart((w) => fixHistogram(w, d.time_to_fix)),
          d.time_to_fix.n ? h("p", { class: "meta-line", style: "margin-top:8px" },
            `Not counted: ${fmt.int(d.time_to_fix.excluded.since_first_release)} windows starting at the first release, ${fmt.int(d.time_to_fix.excluded.still_open)} still open, ${fmt.int(d.time_to_fix.excluded.fix_date_unknown)} with an undated fix.`) : null))),
      panel({ title: "Most advisories", sub: "Tier A packages ranked by unique advisories; click a bar to open the package", aside: aside("tier A only") },
        body((d) => chart((w) => topPackages(w, d.top_packages, (name) => { location.hash = `#/package/${name}`; }))))),
    notes);
}

