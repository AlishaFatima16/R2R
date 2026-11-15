import { getJSON, h, fmt, panel, sevBadge, tierTag, emptyState, errorState, skeleton } from "../lib.js";

const RANK = { critical: 4, high: 3, medium: 2, low: 1, u: 0 };
const COLUMNS = [
  { key: "n", label: "Package", cls: "pkg", sort: (r) => r.n, text: true },
  { key: "tier", label: "Tier", sort: (r) => r.tier || "" , text: true },
  { key: "latest", label: "Latest", sort: (r) => r.latest || "", text: true, hideM: true },
  { key: "releases", label: "Releases", cls: "r", sort: (r) => r.releases },
  { key: "advisories", label: "Advisories", cls: "r", sort: (r) => r.advisories },
  { key: "share", label: "Releases affected", sort: (r) => r.share_affected ?? -1 },
  { key: "severity", label: "Worst severity", sort: (r) => (r.max_level ? RANK[r.max_level] : -1) },
  { key: "last", label: "Last release", sort: (r) => r.last_release || "", hideM: true },
];

function readState() {
  const q = new URLSearchParams((location.hash.split("?")[1] || ""));
  return { q: q.get("q") || "", tier: q.get("tier") || "all", adv: q.get("adv") === "1", sort: q.get("sort") || "advisories", dir: q.get("dir") === "asc" ? "asc" : "desc" };
}
function writeState(state) {
  const q = new URLSearchParams();
  if (state.q) q.set("q", state.q);
  if (state.tier !== "all") q.set("tier", state.tier);
  if (state.adv) q.set("adv", "1");
  if (state.sort !== "advisories") q.set("sort", state.sort);
  if (state.dir !== "desc") q.set("dir", state.dir);
  const text = q.toString();
  history.replaceState(null, "", `#/packages${text ? `?${text}` : ""}`);
}

export function explorer() {
  const state = readState();
  const tableHost = h("div", { class: "table-wrap" }, skeleton(8, 320));
  const count = h("span", { class: "count", "aria-live": "polite" });
  const search = h("input", { class: "field", type: "search", placeholder: "Filter packages", "aria-label": "Filter packages by name or summary", value: state.q, style: "width:min(260px,100%)" });
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Tier" });
  const check = h("input", { type: "checkbox" });
  check.checked = state.adv;
  let rows = [];

  const renderTable = () => {
    const needle = state.q.trim().toLowerCase();
    let list = rows.filter((r) => (state.tier === "all" || r.tier === state.tier)
      && (!state.adv || r.advisories > 0)
      && (!needle || r.n.includes(needle) || (r.s || "").toLowerCase().includes(needle)));
    const col = COLUMNS.find((c) => c.key === state.sort) || COLUMNS[4];
    const sign = state.dir === "asc" ? 1 : -1;
    list = list.slice().sort((a, b) => {
      const x = col.sort(a), y = col.sort(b);
      return (x < y ? -1 : x > y ? 1 : a.n < b.n ? -1 : 1) * sign;
    });
    count.textContent = `${fmt.int(list.length)} of ${fmt.int(rows.length)} packages`;
    if (!list.length) { tableHost.replaceChildren(emptyState("No packages match", "Try clearing the filters.")); return; }
    const head = h("tr", null, COLUMNS.map((c) => h("th", { scope: "col", class: c.cls === "r" ? "r" : "", "aria-sort": state.sort === c.key ? (state.dir === "asc" ? "ascending" : "descending") : null },
      h("button", { type: "button", onclick: () => {
        if (state.sort === c.key) state.dir = state.dir === "asc" ? "desc" : "asc";
        else { state.sort = c.key; state.dir = c.text ? "asc" : "desc"; }
        writeState(state); renderTable();
      } }, c.label, h("span", { class: "arrow", "aria-hidden": "true" }, state.sort === c.key ? (state.dir === "asc" ? "↑" : "↓") : "↕")))));
    const body = list.map((r) => {
      const go = () => { location.hash = `#/package/${r.n}`; };
      const tr = h("tr", { onclick: (e) => { if (!e.target.closest("a")) go(); } },
        h("td", { class: "pkg", "data-label": "Package" }, h("a", { href: `#/package/${r.n}` }, r.n), r.s ? h("span", { class: "sub" }, r.s) : null),
        h("td", { "data-label": "Tier" }, tierTag(r.tier)),
        h("td", { class: "mono hide-m", "data-label": "Latest" }, r.latest || "n/a"),
        h("td", { class: "r", "data-label": "Releases" }, fmt.int(r.releases)),
        h("td", { class: "r", "data-label": "Advisories" }, fmt.int(r.advisories)),
        h("td", { "data-label": "Releases affected" }, r.releases ? h("span", { class: "share", title: `${fmt.int(r.affected_releases)} of ${fmt.int(r.releases)} releases` },
          h("span", { class: "bar" }, h("span", { style: `width:${Math.round((r.share_affected || 0) * 100)}%` })), h("span", { class: "num" }, fmt.pct(r.share_affected))) : "n/a"),
        h("td", { "data-label": "Worst severity" }, r.advisories ? sevBadge(r.max_level === "u" ? null : r.max_level, null, { compact: true }) : h("span", { class: "faint" }, "none")),
        h("td", { class: "num hide-m", "data-label": "Last release" }, fmt.date(r.last_release)));
      return tr;
    });
    tableHost.replaceChildren(h("table", { class: "stackable" }, h("caption", { class: "sr" }, "Tracked packages"), h("thead", null, head), h("tbody", null, body)));
  };

  for (const [key, label] of [["all", "All"], ["A", "Tier A"], ["B", "Tier B"]]) {
    seg.append(h("button", { type: "button", "aria-pressed": String(state.tier === key), onclick: (e) => {
      state.tier = key;
      for (const b of seg.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
      writeState(state); renderTable();
    } }, label));
  }
  search.addEventListener("input", () => { state.q = search.value; writeState(state); renderTable(); });
  check.addEventListener("change", () => { state.adv = check.checked; writeState(state); renderTable(); });

  getJSON("packages.json").then((d) => { rows = d.packages; renderTable(); }).catch((err) => tableHost.replaceChildren(errorState(err, "the package list")));

  return h("div", { class: "view" },
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Packages"),
      h("p", { class: "lede" }, "Every seed package with its release history and advisory exposure. Percentages here are per package; the prevalence numbers on the Overview use tier A only."))),
    h("section", { class: "panel" },
      h("div", { class: "toolbar" }, search, seg, h("label", { class: "check" }, check, "Has advisories"), count),
      tableHost),
    h("p", { class: "notes" }, "Tier B packages were picked for having many advisories, so their shares are not representative of PyPI."));
}
