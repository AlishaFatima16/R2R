// App shell: hash router, sidebar, global search, theme toggle, sample-data banner.

import { getJSON, h, clear, fmt, setTitle, sevBadge, hideTip } from "./lib.js";
import { overview } from "./views/overview.js";
import { explorer } from "./views/explorer.js";
import { packageView } from "./views/package.js";
import { advisoryView, advisoriesView } from "./views/advisory.js";
import { pipelineView } from "./views/pipeline.js";

const $ = (id) => document.getElementById(id);
const main = $("main");

const ctx = {
  setBanner(isSample) { $("banner").hidden = !isSample; },
  setCrumbs(parts) {
    const el = $("crumbs");
    clear(el);
    parts.forEach((p, i) => { if (i) el.append(" / "); el.append(i === parts.length - 1 ? h("b", null, p) : document.createTextNode(p)); });
  },
};

const ROUTES = [
  { re: /^\/?$/, route: "overview", title: "Overview", crumbs: ["Overview"], view: () => overview(ctx) },
  { re: /^\/packages$/, route: "packages", title: "Packages", crumbs: ["Packages"], view: () => explorer(ctx) },
  { re: /^\/package\/([^/]+)$/, route: "packages", title: "Package", crumbs: ["Packages"], view: (m) => packageView(ctx, decodeURIComponent(m[1])) },
  { re: /^\/advisories$/, route: "advisories", title: "Advisories", crumbs: ["Advisories"], view: () => advisoriesView(ctx) },
  { re: /^\/advisory\/(.+)$/, route: "advisories", title: "Advisory", crumbs: ["Advisories"], view: (m) => advisoryView(ctx, decodeURIComponent(m[1])) },
  { re: /^\/pipeline$/, route: "pipeline", title: "Pipeline", crumbs: ["Pipeline"], view: () => pipelineView(ctx) },
];

function render() {
  hideTip();
  closeDrawer();
  const path = (location.hash.slice(1) || "/").split("?")[0];
  const hit = ROUTES.map((r) => ({ r, m: path.match(r.re) })).find((x) => x.m);
  const { r, m } = hit || { r: { route: "", title: "Not found", crumbs: ["Not found"], view: () => h("div", { class: "view" }, h("h1", null, "Page not found"), h("p", { class: "lede" }, "That address does not exist. ", h("a", { href: "#/" }, "Go to the overview"), ".")) }, m: null };
  for (const a of document.querySelectorAll("#nav a")) {
    if (a.dataset.route === r.route) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  ctx.setCrumbs(r.crumbs);
  setTitle(r.title);
  clear(main).append(r.view(m));
  window.scrollTo(0, 0);
  main.focus({ preventScroll: true });
}

// ----------------------------------------------------------------------- sidebar drawer
const sidebar = $("sidebar");
function closeDrawer() {
  sidebar.classList.remove("open");
  $("scrim").classList.remove("on");
  $("menu-btn").setAttribute("aria-expanded", "false");
}
$("menu-btn").addEventListener("click", () => {
  const open = sidebar.classList.toggle("open");
  $("scrim").classList.toggle("on", open);
  $("menu-btn").setAttribute("aria-expanded", String(open));
});
$("scrim").addEventListener("click", closeDrawer);

// ----------------------------------------------------------------------------- theme
function currentTheme() {
  const set = document.documentElement.getAttribute("data-theme");
  return set || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
$("theme-btn").addEventListener("click", () => {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("r2r-theme", next); } catch (e) { /* storage unavailable */ }
});

// ----------------------------------------------------------------------- global search
const input = $("search"), results = $("results");
let index = null, active = -1, items = [];
async function loadIndex() {
  if (index) return index;
  const [p, a] = await Promise.all([getJSON("packages.json"), getJSON("advisories.json")]);
  index = { packages: p.packages, advisories: a.advisories };
  return index;
}
const PAGES = [["Overview", "#/"], ["Packages", "#/packages"], ["Advisories", "#/advisories"], ["Pipeline", "#/pipeline"]];
function setActive(i) {
  active = i;
  [...results.querySelectorAll("a")].forEach((el, n) => el.setAttribute("aria-selected", String(n === i)));
  const el = results.querySelectorAll("a")[i];
  if (el) el.scrollIntoView({ block: "nearest" });
}
function showResults() {
  const q = input.value.trim().toLowerCase();
  clear(results);
  items = [];
  const group = (label) => results.append(h("div", { class: "grp" }, label));
  const add = (node) => { items.push(node); results.append(node); };
  if (!q) {
    group("Go to");
    PAGES.forEach(([label, href]) => add(h("a", { href, role: "option" }, label)));
  } else if (index) {
    const pk = index.packages.filter((p) => p.n.includes(q) || (p.s || "").toLowerCase().includes(q)).sort((a, b) => (b.n.startsWith(q) - a.n.startsWith(q)) || a.n.localeCompare(b.n)).slice(0, 6);
    const ad = index.advisories.filter((a) => a.id.toLowerCase().includes(q) || a.aliases.some((x) => x.toLowerCase().includes(q)) || a.pk.some((n) => n === q)).slice(0, 6);
    if (pk.length) { group("Packages"); pk.forEach((p) => add(h("a", { href: `#/package/${p.n}`, role: "option" }, h("span", { class: "mono" }, p.n), h("span", { class: "faint" }, `${fmt.int(p.advisories)} advisories`)))); }
    if (ad.length) { group("Advisories"); ad.forEach((a) => add(h("a", { href: `#/advisory/${a.id}`, role: "option" }, h("span", { class: "mono" }, a.id), sevBadge(a.l, a.s, { compact: true })))); }
    if (!items.length) results.append(h("div", { class: "empty" }, `No package or advisory matches "${input.value.trim()}".`));
  } else {
    results.append(h("div", { class: "empty" }, "Loading the index…"));
  }
  results.hidden = false;
  input.setAttribute("aria-expanded", "true");
  setActive(items.length ? 0 : -1);
}
const hideResults = () => { results.hidden = true; input.setAttribute("aria-expanded", "false"); };
input.addEventListener("focus", () => { showResults(); loadIndex().then(() => { if (document.activeElement === input) showResults(); }).catch(() => {}); });
input.addEventListener("input", () => { showResults(); loadIndex().then(showResults).catch(() => {}); });
input.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); setActive(Math.min(items.length - 1, active + 1)); }
  else if (e.key === "ArrowUp") { e.preventDefault(); setActive(Math.max(0, active - 1)); }
  else if (e.key === "Enter" && items[active]) { e.preventDefault(); location.hash = items[active].getAttribute("href"); input.value = ""; hideResults(); input.blur(); }
  else if (e.key === "Escape") { hideResults(); input.blur(); }
});
results.addEventListener("mousedown", (e) => { if (e.target.closest("a")) setTimeout(() => { input.value = ""; hideResults(); }, 0); });
document.addEventListener("click", (e) => { if (!e.target.closest(".searchbox")) hideResults(); });
document.addEventListener("keydown", (e) => {
  const typing = /^(input|textarea|select)$/i.test(document.activeElement && document.activeElement.tagName);
  if ((e.key === "/" && !typing && !e.metaKey && !e.ctrlKey) || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k")) {
    e.preventDefault(); input.focus(); input.select();
  }
});

// ---------------------------------------------------------------------------- startup
function sideFoot(d) {
  $("side-foot").replaceChildren(
    h("div", null, h("b", null, d.is_sample ? "Sample data" : "Live export")),
    h("div", null, `Updated ${fmt.date(d.generated_at)}`),
    h("div", null, d.run_id != null ? `Pipeline run #${d.run_id}` : "No pipeline run"));
}
getJSON("overview.json").then((d) => { sideFoot(d); ctx.setBanner(d.is_sample); }).catch(() => {
  $("side-foot").textContent = "Data not found";
});
window.addEventListener("hashchange", render);
render();
