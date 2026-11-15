import { getJSON, h, put, fmt, panel, sevBadge, sampleTag, emptyState, errorState, skeleton, setTitle, LEVELS, daysBetween, copyText } from "../lib.js";

const kindLabel = { introduced: "introduced", fixed: "fixed", last_affected: "last affected", limit: "limit" };

function rangeLine(range) {
  const parts = [];
  range.events.forEach(([kind, version], i) => {
    if (i) parts.push(h("span", { class: "arr", "aria-hidden": "true" }, "→"));
    parts.push(h("span", { class: "ev" }, `${kindLabel[kind] || kind} ${version === "0" ? "(first release)" : version}`));
  });
  return h("div", { class: "range-line", title: range.type }, h("span", { class: "faint" }, range.type.toLowerCase()), parts);
}

function packageSection(pkgFile, id, asOf) {
  const group = pkgFile.advisories.find((g) => g.ids.includes(id));
  if (!group) return null;
  const releases = pkgFile.releases;
  const hit = new Set();
  for (const [a, b] of group.exposed) for (let i = a; i <= b; i++) hit.add(i);
  const chips = [];
  const LIMIT = 150;
  let shown = 0;
  releases.forEach((r, i) => {
    if (!hit.has(i) || shown >= LIMIT) return;
    shown += 1;
    chips.push(h("span", { class: "chip hit", title: r.t ? `Uploaded ${fmt.date(r.t)}` : "No upload date" }, r.v));
  });
  const windows = group.windows.map((w) => h("tr", null,
    h("td", { class: "mono" }, w.from === "0" ? "first release" : w.from),
    h("td", { class: "num" }, fmt.date(w.start)),
    h("td", { class: "mono" }, w.kind === "open" ? h("span", { class: "faint" }, "not fixed") : w.to),
    h("td", { class: "num" }, w.kind === "open" ? "open" : fmt.date(w.end)),
    h("td", { class: "r" }, w.kind === "open" ? fmt.span(daysBetween(w.start, asOf)) : w.start && w.end ? fmt.span(daysBetween(w.start, w.end)) : "n/a")));
  return panel({
    title: pkgFile.package.name, sub: `${fmt.int(group.n_exposed)} of ${fmt.int(releases.length)} releases fall in an affected range`,
    aside: h("a", { class: "btn", href: `#/package/${pkgFile.package.name}` }, "Open package"),
  }, h("div", { class: "stack" },
    group.ranges.length ? h("div", { class: "stack", style: "gap:8px" }, group.ranges.map(rangeLine)) : h("p", { class: "muted" }, "No version range is recorded for this package."),
    group.git_ranges ? h("p", { class: "meta-line" }, `${group.git_ranges} additional range(s) are expressed as git commits and are not evaluated here.`) : null,
    group.windows.length ? h("div", { class: "table-wrap", style: "max-height:none" }, h("table", null,
      h("thead", null, h("tr", null, ["Introduced", "Release date", "Fixed in", "Fix date", "Window"].map((c, i) => h("th", { scope: "col", class: i === 4 ? "r" : "" }, c)))), h("tbody", null, windows))) : null,
    chips.length ? h("div", null, h("p", { class: "meta-line", style: "margin-bottom:6px" }, "Releases in range"),
      h("div", { class: "chips" }, chips), hit.size > LIMIT ? h("p", { class: "meta-line", style: "margin-top:6px" }, `+${hit.size - LIMIT} more not listed`) : null) : null));
}

export function advisoryView(ctx, rawId) {
  const root = h("div", { class: "view" }, h("div", { class: "page-head" }, h("h1", { class: "mono" }, rawId)), skeleton(6, 200));
  getJSON("advisories.json").then(async (index) => {
    const want = rawId.toLowerCase();
    const rec = index.advisories.find((a) => a.id.toLowerCase() === want)
      || index.advisories.find((a) => a.aliases.some((x) => x.toLowerCase() === want) || a.g.toLowerCase() === want);
    ctx.setCrumbs(["Advisories", rawId]);
    if (!rec) {
      put(root, h("div", { class: "page-head" }, h("h1", { class: "mono" }, rawId)),
        emptyState("Advisory not found", "No record with this id or alias is in the exported data."), h("p", { class: "notes" }, h("a", { href: "#/advisories" }, "Browse all advisories")));
      return;
    }
    setTitle(rec.id);
    const files = await Promise.all(rec.pk.map((n) => getJSON(`packages/${encodeURIComponent(n)}.json`).catch(() => null)));
    const group = files.filter(Boolean).flatMap((f) => f.advisories).find((g) => g.ids.includes(rec.id));
    const siblings = index.advisories.filter((a) => a.g === rec.g && a.id !== rec.id);
    const others = rec.aliases.filter((a) => !siblings.some((s) => s.id === a));
    const copy = h("button", { class: "btn", type: "button", onclick: (e) => copyText(rec.id, e.currentTarget) }, "Copy id");
    const kv = [["Published", fmt.date(rec.p)], ["Modified", group ? fmt.date(group.modified) : "n/a"],
      ["Affects", rec.pk.length === 1 ? "1 tracked package" : `${rec.pk.length} tracked packages`]];
    put(root, 
      h("div", { class: "pkg-head" },
        h("div", { class: "pkg-title" }, h("h1", null, rec.id), sevBadge(rec.l, rec.s), index.is_sample ? sampleTag() : null, copy),
        group && group.summary ? h("p", { class: "lede", style: "max-width:80ch" }, group.summary) : null),
      h("div", { class: "split", style: "margin-bottom:16px" },
        panel({ title: "Details" }, h("dl", { class: "kv" }, kv.flatMap(([k, v]) => [h("dt", null, k), h("dd", null, v)]),
          h("dt", null, "Severity"), h("dd", null, rec.l ? `${rec.l[0].toUpperCase()}${rec.l.slice(1)}, CVSS v3 base score ${fmt.score(rec.s)}` : "Unrated: no CVSS v3 vector in the advisory"),
          group && group.vector ? [h("dt", null, group.sev_type === "CVSS_V3" ? "Vector" : `Vector (${group.sev_type})`), h("dd", { class: "mono", style: "font-size:12px" }, group.vector)] : null)),
        panel({ title: "Aliases and related records", sub: "Records sharing a CVE, GHSA or PYSEC id describe the same issue." }, h("div", { class: "chips" },
          siblings.map((a) => h("a", { class: "chip", href: `#/advisory/${a.id}` }, a.id)), others.map((a) => h("span", { class: "chip" }, a)),
          !siblings.length && !others.length ? h("span", { class: "muted" }, "No aliases recorded.") : null))),
      h("div", { class: "stack" }, files.filter(Boolean).map((f) => packageSection(f, rec.id, index.generated_at)).filter(Boolean)),
      files.some((f) => !f) ? h("p", { class: "notes" }, "Some package files could not be loaded.") : null);
  }).catch((err) => put(root, h("div", { class: "page-head" }, h("h1", { class: "mono" }, rawId)), errorState(err, "the advisory index")));
  return root;
}

export function advisoriesView() {
  const state = { q: "", level: "all", limit: 200 };
  const tableHost = h("div", { class: "table-wrap" }, skeleton(8, 300));
  const count = h("span", { class: "count", "aria-live": "polite" });
  const search = h("input", { class: "field", type: "search", placeholder: "Filter by id, CVE or package", "aria-label": "Filter advisories", style: "width:min(280px,100%)" });
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Severity" });
  let all = [];
  const render = () => {
    const needle = state.q.trim().toLowerCase();
    const list = all.filter((a) => (state.level === "all" || (state.level === "unrated" ? !a.l : a.l === state.level))
      && (!needle || a.id.toLowerCase().includes(needle) || a.aliases.some((x) => x.toLowerCase().includes(needle)) || a.pk.some((p) => p.includes(needle))));
    count.textContent = `${fmt.int(list.length)} of ${fmt.int(all.length)} records`;
    if (!list.length) { tableHost.replaceChildren(emptyState("No advisories match", "Try clearing the filters.")); return; }
    const rows = list.slice(0, state.limit).map((a) => h("tr", { onclick: (e) => { if (!e.target.closest("a")) location.hash = `#/advisory/${a.id}`; } },
      h("td", { class: "pkg", "data-label": "Advisory" }, h("a", { href: `#/advisory/${a.id}` }, a.id), a.aliases.length ? h("span", { class: "sub mono" }, a.aliases.slice(0, 2).join(" · ")) : null),
      h("td", { "data-label": "Severity" }, sevBadge(a.l, a.s)),
      h("td", { class: "num", "data-label": "Published" }, fmt.date(a.p)),
      h("td", { class: "mono", "data-label": "Packages" }, a.pk.slice(0, 3).join(", ") + (a.pk.length > 3 ? ` +${a.pk.length - 3}` : ""))));
    const more = list.length > state.limit ? h("div", { class: "panel-foot" }, `Showing ${state.limit} of ${fmt.int(list.length)}. `,
      h("button", { class: "btn", type: "button", onclick: () => { state.limit += 300; render(); } }, "Show more")) : null;
    put(tableHost, h("table", { class: "stackable" }, h("caption", { class: "sr" }, "Advisory records"),
      h("thead", null, h("tr", null, ["Advisory", "Severity", "Published", "Packages"].map((c) => h("th", { scope: "col" }, c)))), h("tbody", null, rows)), more);
  };
  for (const [key, label] of [["all", "All"], ...LEVELS.slice().reverse().map((l) => [l, l[0].toUpperCase() + l.slice(1)]), ["unrated", "Unrated"]]) {
    seg.append(h("button", { type: "button", "aria-pressed": String(state.level === key), onclick: (e) => {
      state.level = key; state.limit = 200;
      for (const b of seg.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
      render();
    } }, label));
  }
  search.addEventListener("input", () => { state.q = search.value; state.limit = 200; render(); });
  getJSON("advisories.json").then((d) => { all = d.advisories; render(); }).catch((err) => tableHost.replaceChildren(errorState(err, "the advisory list")));
  return h("div", { class: "view" },
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Advisories"), h("p", { class: "lede" }, "OSV advisory records that affect tracked packages. GHSA and PYSEC records for the same CVE are listed separately here and merged in the counts."))),
    h("section", { class: "panel" }, h("div", { class: "toolbar" }, search, seg, count), tableHost));
}
