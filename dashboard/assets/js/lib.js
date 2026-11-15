// Shared helpers: DOM builder, data loading, formatting, tooltip, badges, skeletons.

export const LEVELS = ["low", "medium", "high", "critical"];
export const LEVEL_LABEL = { low: "Low", medium: "Medium", high: "High", critical: "Critical", unrated: "Unrated", u: "Unrated" };
const SVG_NS = "http://www.w3.org/2000/svg";

/** Hyperscript. Text children are always text nodes, never HTML, so API text cannot inject markup. */
export function h(tag, attrs, ...children) {
  const el = tag.startsWith("svg:") ? document.createElementNS(SVG_NS, tag.slice(4)) : document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (typeof value === "string" && value.includes("var(") && ["fill", "stroke", "stop-color"].includes(key)) {
      el.style.setProperty(key, value); // var() is not reliable in SVG presentation attributes
    } else el.setAttribute(key, value === true ? "" : value);
  }
  append(el, children);
  return el;
}
export const s = (tag, attrs, ...children) => h("svg:" + tag, attrs, ...children);
function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
}
/** Replace an element's children, skipping null/false so conditional nodes never print as text. */
export function put(el, ...children) { el.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false)); return el; }
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

// ------------------------------------------------------------------------------- data

const cache = new Map();
/** Fetch a JSON file under data/. Results are cached; failures carry a readable message. */
export function getJSON(path) {
  if (!cache.has(path)) {
    const request = fetch(`data/${path}`, { cache: "no-cache" }).then((res) => {
      if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
      return res.json();
    }).catch((err) => {
      cache.delete(path);
      throw err;
    });
    cache.set(path, request);
  }
  return cache.get(path);
}

// ---------------------------------------------------------------------------- formatting

const intFmt = new Intl.NumberFormat("en-US");
export const fmt = {
  int: (n) => (n === null || n === undefined ? "n/a" : intFmt.format(n)),
  pct: (x, digits = 0) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(digits)}%`),
  date: (iso) => (iso ? iso.slice(0, 10) : "n/a"),
  dateTime: (iso) => (iso ? iso.slice(0, 16).replace("T", " ") + " UTC" : "n/a"),
  days(d) {
    if (d === null || d === undefined) return "n/a";
    if (d < 1) return "<1 d";
    if (d < 100) return `${Math.round(d)} d`;
    return `${intFmt.format(Math.round(d))} d`;
  },
  span(d) {
    if (d === null || d === undefined) return "n/a";
    if (d < 60) return `${Math.max(1, Math.round(d))} days`;
    if (d < 730) return `${Math.round(d / 30.4)} months`;
    return `${(d / 365.25).toFixed(1)} years`;
  },
  duration(sec) {
    if (sec === null || sec === undefined) return "n/a";
    if (sec < 90) return `${Math.round(sec)} s`;
    if (sec < 5400) return `${Math.round(sec / 60)} min`;
    return `${(sec / 3600).toFixed(1)} h`;
  },
  score: (v) => (v === null || v === undefined ? "" : v.toFixed(1)),
};
export const daysBetween = (a, b) => (new Date(b) - new Date(a)) / 86400000;

// ------------------------------------------------------------------------------ tooltip

const tooltip = () => document.getElementById("tooltip");
export function showTip(event, nodes) {
  const el = tooltip();
  clear(el);
  append(el, [nodes]);
  el.classList.add("on");
  moveTip(event);
}
export function moveTip(event) {
  const el = tooltip();
  const pad = 14;
  const box = el.getBoundingClientRect();
  let x = event.clientX + pad;
  let y = event.clientY + pad;
  if (x + box.width > window.innerWidth - 8) x = event.clientX - box.width - pad;
  if (y + box.height > window.innerHeight - 8) y = event.clientY - box.height - pad;
  el.style.left = `${Math.max(8, x)}px`;
  el.style.top = `${Math.max(8, y)}px`;
}
export function hideTip() { tooltip().classList.remove("on"); }
/** Tooltip on pointer hover and on keyboard focus. */
export function tip(el, build) {
  el.addEventListener("pointerenter", (e) => showTip(e, build()));
  el.addEventListener("pointermove", moveTip);
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("focus", () => {
    const r = el.getBoundingClientRect();
    showTip({ clientX: r.left + r.width / 2, clientY: r.top }, build());
  });
  el.addEventListener("blur", hideTip);
}
export const row = (label, value) => h("div", { class: "row" }, h("span", { class: "dim" }, label), h("b", null, value));

// ------------------------------------------------------------------------------- badges

export function sevBadge(level, score, { compact = false } = {}) {
  const key = level || "unrated";
  return h("span", { class: `badge sev-${key}`, title: level ? `${LEVEL_LABEL[key]}${score != null ? ` (CVSS ${fmt.score(score)})` : ""}` : "No CVSS v3 score available" },
    h("i"), LEVEL_LABEL[key], !compact && score != null ? h("span", { class: "score" }, fmt.score(score)) : null);
}
export const tierTag = (tier) => h("span", { class: "tag", title: tier === "A" ? "Tier A: most downloaded. Used for prevalence statistics." : "Tier B: extra packages with many advisories. Excluded from prevalence statistics." }, tier ? `Tier ${tier}` : "Tier n/a");
export const sampleTag = () => h("span", { class: "tag dashed", title: "Built from fixtures, not a full run" }, "sample");
export const tierATag = () => h("span", { class: "tag", title: "Prevalence statistics use tier A packages only (the most downloaded). Tier B was chosen for having many advisories and would bias them." }, "tier A only");
export const mono = (text) => h("span", { class: "mono" }, text);

// ------------------------------------------------------------------------ view scaffolding

export function skeleton(lines = 3, height) {
  return h("div", { "aria-hidden": "true", style: height ? `height:${height}px` : null },
    Array.from({ length: lines }, (_, i) => h("div", { class: "sk sk-line", style: `width:${90 - ((i * 17) % 40)}%` })));
}
export function emptyState(title, text) { return h("div", { class: "empty-state" }, h("b", null, title), text); }
export function errorState(err, what = "this data") {
  return h("div", { class: "error-state", role: "alert" }, h("b", null, `Could not load ${what}.`), h("br"),
    String(err && err.message ? err.message : err), h("br"),
    "If you opened index.html directly from disk, serve the folder instead: python -m http.server inside dashboard/.");
}

/** A titled panel. Pass a body element, or a function that fills it (async allowed). */
export function panel({ title, sub, aside, flush = false, className = "" }, body) {
  const host = h("div", { class: `panel-body${flush ? " flush" : ""}` });
  const node = h("section", { class: `panel ${className}`.trim() },
    h("div", { class: "panel-head" }, h("h2", null, title), aside || null),
    sub ? h("p", { class: "panel-sub" }, sub) : null, host);
  if (typeof body === "function") {
    host.append(skeleton(4, 180));
    Promise.resolve().then(body).then((content) => { clear(host); if (content) append(host, [content]); })
      .catch((err) => { clear(host); host.append(errorState(err)); });
  } else if (body) append(host, [body]);
  return Object.assign(node, { host });
}

/** Redraw an SVG chart whenever its container changes width. */
export function responsive(host, draw) {
  let width = 0;
  const run = (force) => {
    const w = Math.floor(host.clientWidth);
    if (!w || (w === width && !force)) return;
    width = w;
    clear(host);
    try { host.append(draw(w)); } catch (err) { host.append(errorState(err, "this chart")); }
  };
  const observer = new ResizeObserver(() => requestAnimationFrame(() => run(false)));
  observer.observe(host);
  run(false);
  const redraw = () => run(true);
  redraw.stop = () => observer.disconnect();
  return redraw;
}

export function copyText(text, button) {
  const done = () => { const old = button.textContent; button.textContent = "Copied"; setTimeout(() => (button.textContent = old), 1200); };
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => {});
}

export function setTitle(text) { document.title = text ? `${text} · R2R Risk Observatory` : "R2R Risk Observatory"; }
