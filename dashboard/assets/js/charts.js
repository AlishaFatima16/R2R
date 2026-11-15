// Hand-drawn SVG charts. Colour is used only for severity; everything else is neutral.

import { LEVELS, LEVEL_LABEL, fmt, h, s, tip, row, emptyState } from "./lib.js";

const root = (width, height, label) => s("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": label });

function niceMax(value) {
  if (value <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) if (value <= step * pow) return step * pow;
  return 10 * pow;
}
const ticks = (max, n = 4) => Array.from({ length: n + 1 }, (_, i) => (max / n) * i);

/** Advisories published per year, stacked by severity. Critical sits on the axis. */
export function advisoriesByYear(width, rows) {
  if (!rows.length) return emptyState("No advisories yet", "No published advisories affect the tracked packages.");
  const keys = ["critical", "high", "medium", "low", "unrated"];
  const height = 250, m = { t: 18, r: 96, b: 26, l: 30 };
  const iw = width - m.l - m.r, ih = height - m.t - m.b;
  const totals = rows.map((r) => keys.reduce((a, k) => a + (r[k] || 0), 0));
  const max = niceMax(Math.max(...totals));
  const y = (v) => m.t + ih - (v / max) * ih;
  const step = iw / rows.length, bw = Math.max(4, Math.min(28, step * 0.62));
  const total = keys.map((k) => rows.reduce((a, r) => a + (r[k] || 0), 0));
  const summary = `Advisories published per year by severity, ${rows[0].year} to ${rows.at(-1).year}. Total ${total.reduce((a, b) => a + b, 0)}.`;
  const svg = root(width, height, summary);
  for (const t of ticks(max)) {
    svg.append(s("line", { class: "grid", x1: m.l, x2: m.l + iw, y1: y(t), y2: y(t) }),
      s("text", { x: m.l - 6, y: y(t) + 3.5, "text-anchor": "end" }, fmt.int(t)));
  }
  rows.forEach((r, i) => {
    const x = m.l + step * i + (step - bw) / 2;
    let acc = 0;
    for (const k of keys) {
      const v = r[k] || 0;
      if (!v) continue;
      svg.append(s("rect", { class: `fill-${k}`, x, y: y(acc + v), width: bw, height: Math.max(1, y(acc) - y(acc + v) - 1), rx: 1.5 }));
      acc += v;
    }
    if (acc) svg.append(s("text", { class: "strong", x: x + bw / 2, y: y(acc) - 5, "text-anchor": "middle" }, acc));
    const show = rows.length <= 8 || i % Math.ceil(rows.length / 8) === 0 || i === rows.length - 1;
    if (show) svg.append(s("text", { x: x + bw / 2, y: height - 8, "text-anchor": "middle" }, r.year));
    const hit = s("rect", { class: "hit", x: m.l + step * i, y: m.t, width: step, height: ih, tabindex: 0, "aria-label": `${r.year}: ${acc} advisories` });
    tip(hit, () => h("div", null, h("b", null, r.year), ...keys.filter((k) => r[k]).map((k) => row(LEVEL_LABEL[k], r[k])), row("Total", acc)));
    svg.append(hit);
  });
  svg.append(s("line", { class: "axis", x1: m.l, x2: m.l + iw, y1: m.t + ih, y2: m.t + ih }));
  // Direct labels with totals, stacked top-down in the right margin.
  let ly = m.t + 6;
  keys.slice().reverse().forEach((k) => {
    const v = total[keys.indexOf(k)];
    if (!v) return;
    svg.append(s("rect", { class: `fill-${k}`, x: m.l + iw + 14, y: ly - 8, width: 9, height: 9, rx: 2 }),
      s("text", { x: m.l + iw + 28, y: ly, class: "strong" }, `${LEVEL_LABEL[k]} ${v}`));
    ly += 18;
  });
  return svg;
}

/** Share of the releases published each year that fall in some advisory's affected range. */
export function affectedByYear(width, rows) {
  if (!rows.length) return emptyState("No releases", "No release dates are available for tier A packages.");
  const height = 250, m = { t: 20, r: 54, b: 26, l: 36 };
  const iw = width - m.l - m.r, ih = height - m.t - m.b;
  const x = (i) => m.l + (rows.length === 1 ? iw / 2 : (iw * i) / (rows.length - 1));
  const y = (v) => m.t + ih - v * ih;
  const svg = root(width, height, `Share of tier A releases affected by at least one advisory, by release year, ${rows[0].year} to ${rows.at(-1).year}.`);
  for (const t of [0, 0.25, 0.5, 0.75, 1]) {
    svg.append(s("line", { class: "grid", x1: m.l, x2: m.l + iw, y1: y(t), y2: y(t) }),
      s("text", { x: m.l - 6, y: y(t) + 3.5, "text-anchor": "end" }, `${Math.round(t * 100)}%`));
  }
  svg.append(s("path", { d: rows.map((r, i) => `${i ? "L" : "M"}${x(i)},${y(r.share)}`).join(""), fill: "none", stroke: "var(--text)", "stroke-width": 1.5, "stroke-linejoin": "round" }));
  rows.forEach((r, i) => {
    const thin = r.releases < 10;
    svg.append(s("circle", { cx: x(i), cy: y(r.share), r: 3, fill: thin ? "var(--surface)" : "var(--text)", stroke: "var(--text)", "stroke-width": 1.5 }));
    const show = rows.length <= 8 || i % Math.ceil(rows.length / 8) === 0 || i === rows.length - 1;
    if (show) svg.append(s("text", { x: x(i), y: height - 8, "text-anchor": "middle" }, r.year));
    const hit = s("rect", { class: "hit", x: x(i) - (iw / rows.length) / 2, y: m.t, width: Math.max(12, iw / rows.length), height: ih, tabindex: 0, "aria-label": `${r.year}: ${fmt.pct(r.share)} of ${r.releases} releases affected` });
    tip(hit, () => h("div", null, h("b", null, `Released in ${r.year}`), row("Affected", `${fmt.int(r.affected)} of ${fmt.int(r.releases)}`), row("Share", fmt.pct(r.share, 1)),
      thin ? h("div", { class: "dim" }, "Fewer than 10 releases: read with care") : null));
    svg.append(hit);
  });
  const last = rows.at(-1);
  svg.append(s("text", { class: "strong", x: x(rows.length - 1) + 8, y: y(last.share) + 4 }, fmt.pct(last.share)));
  return svg;
}

const SHORT = { "under 1 week": "<1w", "1-4 weeks": "1-4w", "1-3 months": "1-3m", "3-6 months": "3-6m", "6-12 months": "6-12m", "1-2 years": "1-2y", "2-5 years": "2-5y", "over 5 years": "5y+" };

/** Histogram of exposure-window lengths, with the bin that holds the median marked. */
export function fixHistogram(width, data) {
  const bins = data.bins;
  if (!data.n) return emptyState("No closed windows", "No advisory has both a known introduced release and a dated fix release.");
  const height = 250, m = { t: 34, r: 8, b: 44, l: 30 };
  const iw = width - m.l - m.r, ih = height - m.t - m.b;
  const max = niceMax(Math.max(...bins.map((b) => b.count)));
  const y = (v) => m.t + ih - (v / max) * ih;
  const step = iw / bins.length, bw = step * 0.7;
  const medianBin = bins.findIndex((b) => data.median_days >= b.from && (b.to === null || data.median_days < b.to));
  const svg = root(width, height, `Time from introduced release to fixed release for ${data.n} closed exposure windows. Median ${Math.round(data.median_days)} days.`);
  for (const t of ticks(max)) {
    svg.append(s("line", { class: "grid", x1: m.l, x2: m.l + iw, y1: y(t), y2: y(t) }),
      s("text", { x: m.l - 6, y: y(t) + 3.5, "text-anchor": "end" }, fmt.int(t)));
  }
  bins.forEach((b, i) => {
    const bx = m.l + step * i + (step - bw) / 2;
    const isMedian = i === medianBin;
    svg.append(s("rect", { x: bx, y: y(b.count), width: bw, height: Math.max(0, m.t + ih - y(b.count)), rx: 2, fill: isMedian ? "var(--text)" : "var(--mark)" }));
    if (b.count) svg.append(s("text", { class: "strong", x: bx + bw / 2, y: y(b.count) - 5, "text-anchor": "middle" }, b.count));
    if (width < 520) {
      svg.append(s("text", { x: bx + bw / 2, y: height - 20, "text-anchor": "middle" }, SHORT[b.label] || b.label));
    } else {
      const label = b.label.split(" ");
      const mid = Math.ceil(label.length / 2);
      svg.append(s("text", { x: bx + bw / 2, y: height - 26, "text-anchor": "middle" }, label.slice(0, mid).join(" ")),
        s("text", { x: bx + bw / 2, y: height - 13, "text-anchor": "middle" }, label.slice(mid).join(" ")));
    }
    const hit = s("rect", { class: "hit", x: m.l + step * i, y: m.t, width: step, height: ih, tabindex: 0, "aria-label": `${b.label}: ${b.count} windows` });
    tip(hit, () => h("div", null, h("b", null, b.label), row("Windows", b.count)));
    svg.append(hit);
  });
  svg.append(s("line", { class: "axis", x1: m.l, x2: m.l + iw, y1: m.t + ih, y2: m.t + ih }));
  if (medianBin >= 0) {
    const cx = m.l + step * medianBin + step / 2;
    svg.append(s("text", { class: "strong", x: Math.min(Math.max(cx, m.l + 60), m.l + iw - 60), y: 14, "text-anchor": "middle" }, `median ${fmt.int(Math.round(data.median_days))} days`));
  }
  return svg;
}

/** Horizontal bars: tier A packages with the most unique advisories. */
export function topPackages(width, rows, onOpen) {
  if (!rows.length) return emptyState("No advisories", "None of the tier A packages has an advisory yet.");
  const narrow = width < 520;
  const rowH = 28, m = { t: 4, r: 8, b: 4, l: narrow ? 98 : 132 };
  const height = m.t + m.b + rows.length * rowH;
  const iw = width - m.l - m.r - (narrow ? 84 : 150);
  const max = Math.max(...rows.map((r) => r.advisories));
  const svg = root(width, height, `Tier A packages with the most unique advisories. Top: ${rows[0].name} with ${rows[0].advisories}.`);
  rows.forEach((r, i) => {
    const yy = m.t + i * rowH, w = Math.max(2, (r.advisories / max) * iw);
    const g = s("g", { tabindex: 0, role: "link", "aria-label": `${r.name}: ${r.advisories} advisories`, style: "cursor:pointer" });
    g.append(s("rect", { class: "hit", x: 0, y: yy, width, height: rowH }),
      s("text", { class: "strong mono", x: m.l - 18, y: yy + 18, "text-anchor": "end" }, r.name.length > (narrow ? 11 : 16) ? r.name.slice(0, narrow ? 10 : 15) + "…" : r.name),
      s("rect", { x: m.l, y: yy + 7, width: w, height: 14, rx: 2, fill: "var(--mark-strong)" }),
      s("text", { class: "strong", x: m.l + w + 8, y: yy + 18 }, r.advisories),
      s("text", { x: m.l + w + 8 + String(r.advisories).length * 7 + 6, y: yy + 18 }, narrow ? fmt.pct(r.share_affected) : `${fmt.pct(r.share_affected)} of releases`));
    if (r.max_level) g.append(s("rect", { class: `fill-${r.max_level}`, x: m.l - 12, y: yy + 10, width: 8, height: 8, rx: 2 }));
    g.addEventListener("click", () => onOpen(r.name));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter") onOpen(r.name); });
    tip(g, () => h("div", null, h("b", { class: "m" }, r.name), row("Unique advisories", r.advisories), row("Releases affected", fmt.pct(r.share_affected, 1)), row("Worst severity", LEVEL_LABEL[r.max_level || "unrated"])));
    svg.append(g);
  });
  return svg;
}

export { LEVELS };
