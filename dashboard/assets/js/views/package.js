import { getJSON, h, put, fmt, panel, sevBadge, tierTag, sampleTag, emptyState, errorState, skeleton, setTitle } from "../lib.js";
import { timeline } from "../timeline.js";

const stat = (label, value, sub) => h("div", { class: "stat" }, h("div", { class: "stat-label" }, label),
  h("div", { class: "stat-value" }, value), h("div", { class: "stat-sub" }, sub));

function advisoriesTable(pkg) {
  const groups = pkg.advisories;
  if (!groups.length) return emptyState("No advisories", "OSV lists no published advisory for this package.");
  const total = pkg.releases.length;
  const body = groups.map((g) => {
    const go = () => { location.hash = `#/advisory/${g.ids[0]}`; };
    return h("tr", { onclick: (e) => { if (!e.target.closest("a")) go(); } },
      h("td", { class: "pkg", "data-label": "Advisory" }, h("a", { href: `#/advisory/${g.ids[0]}` }, g.id),
        h("span", { class: "sub" }, g.summary || g.ids.join(" · "))),
      h("td", { "data-label": "Severity" }, sevBadge(g.level, g.score)),
      h("td", { class: "num", "data-label": "Published" }, fmt.date(g.published)),
      h("td", { class: "mono", "data-label": "Fixed in" }, g.fixed_in.length ? g.fixed_in.slice(0, 3).join(", ") + (g.fixed_in.length > 3 ? ` +${g.fixed_in.length - 3}` : "") : h("span", { class: "faint" }, "not fixed")),
      h("td", { class: "r", "data-label": "Releases", title: `${g.n_exposed} of ${total} releases` }, fmt.int(g.n_exposed)));
  });
  return h("div", { class: "table-wrap", style: "max-height:520px" }, h("table", { class: "stackable" }, h("caption", { class: "sr" }, "Advisories for this package"),
    h("thead", null, h("tr", null, h("th", { scope: "col" }, "Advisory"), h("th", { scope: "col" }, "Severity"), h("th", { scope: "col" }, "Published"), h("th", { scope: "col" }, "Fixed in"), h("th", { scope: "col", class: "r" }, "Releases"))),
    h("tbody", null, body)));
}

function dependenciesBody(pkg, tracked) {
  const dep = pkg.dependencies;
  if (!dep || !dep.items.length) {
    return emptyState("No dependency data", dep && dep.release ? `Nothing was recorded for ${dep.release}. Dependencies are only stored for releases whose per-release metadata was fetched.` : "No release to read dependencies from.");
  }
  const rows = dep.items.map((d) => {
    const name = tracked.has(d.name) ? h("a", { class: "dep-name", href: `#/package/${d.name}` }, d.name) : h("span", { class: "dep-name" }, d.name);
    return h("div", { class: "dep-row", style: `padding-left:${16 + (d.depth - 1) * 18}px` },
      d.depth > 1 ? h("span", { class: "faint", "aria-hidden": "true" }, "└") : null, name,
      d.version ? h("span", { class: "dep-spec" }, d.version) : d.spec ? h("span", { class: "dep-spec" }, d.spec) : null,
      h("span", { class: "dep-meta" },
        d.valid === false ? h("span", { class: "tag", title: d.raw || "" }, "invalid requirement") : null,
        d.extra_only ? h("span", { class: "tag", title: d.marker || "" }, "extra only") : d.conditional ? h("span", { class: "tag", title: d.marker || "" }, "conditional") : null,
        h("span", { class: "tag", title: d.relation === "INDIRECT" ? "Pulled in by another dependency" : "Declared by this release" }, `depth ${d.depth}`)));
  });
  const more = dep.total > dep.items.length ? h("div", { class: "panel-foot" }, `Showing ${dep.items.length} of ${dep.total}.`) : null;
  return h("div", null, h("div", null, rows), more);
}

export function packageView(ctx, name) {
  const root = h("div", { class: "view" }, h("div", { class: "page-head" }, h("h1", { class: "mono" }, name)), skeleton(6, 240));
  Promise.all([getJSON(`packages/${encodeURIComponent(name)}.json`), getJSON("packages.json")]).then(([pkg, list]) => {
    const p = pkg.package, st = pkg.stats;
    setTitle(p.display || p.name);
    ctx.setCrumbs(["Packages", p.name]);
    const tracked = new Set(list.packages.map((r) => r.n));
    const links = [
      h("span", null, `Latest `, h("span", { class: "mono" }, p.latest || "n/a")),
      p.license ? h("span", null, `License ${p.license}`) : null,
      h("a", { href: `https://pypi.org/project/${encodeURIComponent(p.name)}/`, target: "_blank", rel: "noopener noreferrer" }, "PyPI page ↗"),
      p.repo_url && /^https?:\/\//.test(p.repo_url) ? h("a", { href: p.repo_url, target: "_blank", rel: "noopener noreferrer" }, "Project link ↗") : null,
    ];
    put(root, 
      h("div", { class: "pkg-head" },
        h("div", { class: "pkg-title" }, h("h1", null, p.name), tierTag(p.tier), pkg.is_sample ? sampleTag() : null,
          st.latest_affected ? h("span", { class: "tag solid", title: "The latest release is inside an advisory's affected range" }, "latest release affected") : null),
        p.summary ? h("p", { class: "lede" }, p.summary) : null, h("div", { class: "link-row" }, links)),
      h("div", { class: "stats stats-4" },
        stat("Releases", fmt.int(st.releases), `${fmt.date(st.first_release)} to ${fmt.date(st.last_release)}`),
        stat("Advisories", fmt.int(st.advisories), `${fmt.int(st.records)} records, merged by alias`),
        stat("Releases affected", st.share_affected == null ? "n/a" : fmt.pct(st.share_affected, 1), `${fmt.int(st.affected_releases)} of ${fmt.int(st.releases)}${p.tier === "B" ? " · tier B, not used for prevalence" : ""}`),
        stat("Median time to fix", st.median_fix_days == null ? "n/a" : h("span", null, fmt.int(Math.round(st.median_fix_days)), h("small", null, "days")), `${st.fix_windows} closed windows`)),
      panel({ title: "Release timeline", sub: "Each tick is a release. Coloured ticks fall inside an advisory's affected range. Bands below show how long each exposure window stayed open: introduced release to fixed release.", className: "tl-panel" },
        timeline(pkg, { asOf: pkg.generated_at, onOpen: (id) => { location.hash = `#/advisory/${id}`; } })),
      h("div", { class: "grid-main", style: "margin-top:16px" },
        panel({ title: "Advisories", sub: `${st.advisories} unique, newest first. A GHSA and a PYSEC record for the same CVE count once.`, flush: true }, advisoriesTable(pkg)),
        panel({ title: "Dependencies", sub: pkg.dependencies && pkg.dependencies.release ? `Latest release ${pkg.dependencies.release} · ${pkg.dependencies.source === "resolved" ? "resolved graph from deps.dev" : "direct requirements as published"}` : "Latest release", flush: true }, dependenciesBody(pkg, tracked))));
  }).catch((err) => {
    ctx.setCrumbs(["Packages", name]);
    put(root, h("div", { class: "page-head" }, h("h1", { class: "mono" }, name)),
      errorState(err, `the package "${name}"`), h("p", { class: "notes" }, h("a", { href: "#/packages" }, "Back to all packages")));
  });
  return root;
}
