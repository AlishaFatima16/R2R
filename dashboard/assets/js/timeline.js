// The release timeline strip: every release is a tick on a time axis; advisory exposure windows
// (introduced -> fixed) are bands underneath, so you can see when versions were vulnerable.

import { LEVEL_LABEL, daysBetween, fmt, h, s, showTip, moveTip, hideTip, tip, row, responsive, emptyState } from "./lib.js";

const PRESETS = [["all", "All time"], ["10", "10 y"], ["5", "5 y"], ["2", "2 y"], ["1", "1 y"]];
const LANE = 18, BAND = 13, TOP = 30, TICKS_H = 30, FIRST_LANE_Y = TOP + TICKS_H + 14, MAX_LANES = 8;
const levelOf = (v) => v || "unrated";

function axisTicks(t0, t1, width) {
  const months = (t1 - t0) / 2629800000;
  const target = Math.max(2, Math.floor(width / 78));
  const step = [1, 3, 6, 12, 24, 60].find((m) => months / m <= target) || 120;
  const out = [];
  const d = new Date(t0);
  d.setUTCDate(1); d.setUTCHours(0, 0, 0, 0);
  if (step >= 12) d.setUTCMonth(0); else d.setUTCMonth(Math.floor(d.getUTCMonth() / step) * step);
  while (d.getTime() <= t1) {
    if (d.getTime() >= t0) {
      const label = step >= 12 ? String(d.getUTCFullYear()) : d.toLocaleString("en-US", { month: "short", year: "2-digit", timeZone: "UTC" });
      out.push({ t: d.getTime(), label });
    }
    d.setUTCMonth(d.getUTCMonth() + step);
  }
  return out;
}

/** Build the timeline card body. pkg is a packages/<name>.json payload. */
export function timeline(pkg, { asOf, onOpen }) {
  const now = new Date(asOf).getTime();
  const releases = pkg.releases.map((r, i) => ({ ...r, i, ms: r.t ? new Date(r.t).getTime() : 0 })).filter((r) => r.t);
  if (!releases.length) return emptyState("No dated releases", "This package has no releases with an upload date, so there is nothing to place on a timeline.");

  const bands = [];
  let undated = 0;
  for (const g of pkg.advisories) {
    for (const w of g.windows) {
      if (!w.start || !w.end) { undated += 1; continue; }
      bands.push({ g, w, s: new Date(w.start).getTime(), e: new Date(w.end).getTime() });
    }
  }
  const state = { preset: "all", allLanes: false };
  const t0All = Math.min(...releases.map((r) => r.ms), ...bands.map((b) => b.s));
  const host = h("div", { class: "tl" });
  const note = h("div", { class: "tl-note" });
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Time range" });

  const draw = (width) => {
    const range = state.preset === "all" ? 0 : Number(state.preset) * 31557600000;
    const t0 = range ? Math.max(t0All, now - range) : t0All;
    const m = { l: 14, r: 64 };
    const iw = Math.max(80, width - m.l - m.r);
    const x = (ms) => m.l + ((ms - t0) / (now - t0)) * iw;
    const visible = bands.filter((b) => b.e >= t0).sort((a, b) => a.s - b.s || a.e - b.e);
    const laneEnd = [];
    for (const b of visible) {
      const x0 = x(Math.max(b.s, t0)), x1 = Math.max(x(b.e), x0 + 3);
      let lane = laneEnd.findIndex((end) => end + 4 < x0);
      if (lane < 0) { lane = laneEnd.length; laneEnd.push(0); }
      laneEnd[lane] = x1;
      Object.assign(b, { lane, x0, x1 });
    }
    const lanes = laneEnd.length;
    const shown = state.allLanes ? lanes : Math.min(lanes, MAX_LANES);
    const height = FIRST_LANE_Y + Math.max(shown, 1) * LANE + 12;
    const inRange = releases.filter((r) => r.ms >= t0);
    const exposed = inRange.filter((r) => r.a).length;
    const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img",
      "aria-label": `Release timeline for ${pkg.package.name}: ${inRange.length} releases, ${exposed} inside an advisory's affected range, ${visible.length} exposure windows.` });
    svg.append(s("defs", null, s("pattern", { id: "hatch", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
      s("line", { x1: 0, y1: 0, x2: 0, y2: 6, stroke: "var(--surface)", "stroke-width": 2.2, opacity: 0.6 }))));
    for (const t of axisTicks(t0, now, width)) {
      svg.append(s("line", { class: "grid", x1: x(t.t), x2: x(t.t), y1: TOP - 6, y2: height - 6, style: "stroke:var(--line);stroke-width:1" }),
        s("text", { x: x(t.t) + 4, y: TOP - 12 }, t.label));
    }
    svg.append(s("line", { x1: x(now), x2: x(now), y1: TOP - 6, y2: height - 6, stroke: "var(--mark-strong)", "stroke-dasharray": "3 3" }),
      s("text", { x: x(now) + 5, y: TOP - 12, class: "strong" }, "now"));

    // release ticks: neutral first, exposed on top so their colour is never hidden
    const base = TOP + TICKS_H;
    const tick = (r) => {
      const hh = r.p ? 14 : 24;
      const colour = r.a ? `var(--sev-${r.s === "u" ? "unrated" : r.s})` : "var(--mark)";
      return s("line", { class: "tick", x1: x(r.ms), x2: x(r.ms), y1: base - hh, y2: base, stroke: colour, "stroke-width": r.a ? 1.8 : 1.3, "stroke-dasharray": r.y ? "2 2" : null });
    };
    inRange.filter((r) => !r.a).forEach((r) => svg.append(tick(r)));
    inRange.filter((r) => r.a).forEach((r) => svg.append(tick(r)));
    svg.append(s("line", { x1: m.l, x2: m.l + iw, y1: base + 0.5, y2: base + 0.5, style: "stroke:var(--line-strong);stroke-width:1" }));
    const latest = inRange.filter((r) => !r.p).at(-1) || inRange.at(-1);
    if (latest) svg.append(s("text", { class: "strong", x: Math.min(x(latest.ms), width - 8), y: base + 12, "text-anchor": "end" }, `latest ${latest.v}`));

    // bands
    visible.filter((b) => b.lane < shown).forEach((b) => {
      const open = b.w.kind === "open";
      const y = FIRST_LANE_Y + b.lane * LANE;
      const lv = levelOf(b.g.level);
      const wd = Math.max(3, b.x1 - b.x0);
      const label = `${b.g.id}, ${LEVEL_LABEL[lv]}, ${b.w.from === "0" ? "since first release" : `introduced ${b.w.from}`}${open ? ", not fixed" : `, fixed ${b.w.to}`}`;
      const grp = s("g", { tabindex: 0, role: "link", "aria-label": label });
      grp.append(s("rect", { class: `band fill-${lv}`, x: b.x0, y, width: wd, height: BAND, rx: 2.5, style: `stroke:var(--sev-${lv === "unrated" ? "unrated" : lv + "-ink"})` }));
      if (open) grp.append(s("rect", { x: b.x0, y, width: wd, height: BAND, rx: 2.5, fill: "url(#hatch)", "pointer-events": "none" }));
      const chars = Math.floor((wd - 10) / 6);
      if (chars >= 8) {
        const text = b.g.id.length > chars ? b.g.id.slice(0, chars - 1) + "…" : b.g.id;
        grp.append(s("text", { class: "band-label", x: b.x0 + 5, y: y + 9.5, style: `fill:var(--sev-${lv === "unrated" ? "low" : lv}-on)` }, lv === "unrated" ? "" : text),
          lv === "unrated" ? s("text", { class: "band-label", x: b.x0 + 5, y: y + 9.5, style: "fill:var(--text)" }, text) : null);
      }
      grp.addEventListener("click", () => onOpen(b.g.ids[0]));
      grp.addEventListener("keydown", (e) => { if (e.key === "Enter") onOpen(b.g.ids[0]); });
      tip(grp, () => h("div", null,
        h("b", { class: "m" }, b.g.id), h("div", { class: "dim" }, `${LEVEL_LABEL[lv]}${b.g.score != null ? ` · CVSS ${fmt.score(b.g.score)}` : ""}`),
        row("Introduced", b.w.origin ? `first release (${fmt.date(b.w.start)})` : `${b.w.from} (${fmt.date(b.w.start)})`),
        row(open ? "Fixed" : b.w.kind === "last_affected" ? "Last affected" : "Fixed", open ? "not yet" : `${b.w.to} (${fmt.date(b.w.end)})`),
        row("Window", open ? `${fmt.span(daysBetween(b.w.start, asOf))} and open` : fmt.span(daysBetween(b.w.start, b.w.end))),
        h("div", { class: "dim" }, "Click to open the advisory")));
      svg.append(grp);
    });
    if (!visible.length) svg.append(s("text", { x: m.l, y: FIRST_LANE_Y + 12 }, "No exposure windows in this range."));

    // crosshair and nearest-release tooltip
    const cross = s("line", { class: "cross", x1: 0, x2: 0, y1: TOP - 6, y2: base, visibility: "hidden" });
    svg.append(cross);
    const sensor = s("rect", { x: m.l, y: TOP - 6, width: iw, height: TICKS_H + 6, fill: "transparent" });
    sensor.addEventListener("pointermove", (e) => {
      const box = svg.getBoundingClientRect();
      const px = ((e.clientX - box.left) / box.width) * width;
      let best = null, dist = 9;
      for (const r of inRange) { const d = Math.abs(x(r.ms) - px); if (d < dist) { dist = d; best = r; } }
      cross.setAttribute("x1", px); cross.setAttribute("x2", px); cross.setAttribute("visibility", "visible");
      if (!best) { hideTip(); return; }
      const hits = pkg.advisories.filter((g) => g.exposed.some(([a, b]) => best.i >= a && best.i <= b));
      showTip(e, h("div", null, h("b", { class: "m" }, best.v), h("div", { class: "dim" }, fmt.date(best.t) + (best.y ? " · yanked" : "") + (best.p ? " · pre/dev" : "")),
        row("Advisories", best.a ? `${best.a} (worst: ${LEVEL_LABEL[levelOf(best.s)]})` : "none"),
        ...hits.slice(0, 3).map((g) => h("div", { class: "m dim" }, g.id)), hits.length > 3 ? h("div", { class: "dim" }, `+${hits.length - 3} more`) : null));
      moveTip(e);
    });
    sensor.addEventListener("pointerleave", () => { cross.setAttribute("visibility", "hidden"); hideTip(); });
    svg.append(sensor);

    // notes under the chart
    note.replaceChildren(...[
      h("span", null, h("i", { class: "key-tick" }), `${fmt.int(inRange.length)} releases, ${fmt.int(exposed)} inside an affected range`),
      h("span", null, h("i", { class: "key-band" }), "closed window: introduced to fixed release"),
      h("span", null, h("i", { class: "key-open" }), "hatched: no fix yet"),
      lanes > MAX_LANES ? h("button", { class: "btn", onclick: () => { state.allLanes = !state.allLanes; redraw(); } }, state.allLanes ? "Show fewer windows" : `Show all ${lanes} rows of windows`) : null,
      undated ? h("span", null, `${undated} window${undated > 1 ? "s" : ""} not drawn: fix release has no upload date`) : null,
    ].filter(Boolean));
    return svg;
  };

  const controls = h("div", { class: "tl-controls" }, seg);
  let redraw = () => {};
  for (const [key, label] of PRESETS) {
    seg.append(h("button", { type: "button", "aria-pressed": String(key === state.preset), onclick: (e) => {
      state.preset = key;
      for (const b of seg.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
      redraw();
    } }, label));
  }
  redraw = responsive(host, draw);
  return h("div", null, controls, h("div", { style: "padding:8px 0 4px" }, host), note);
}
