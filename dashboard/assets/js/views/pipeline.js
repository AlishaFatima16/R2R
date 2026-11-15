import { getJSON, h, put, fmt, panel, sampleTag, emptyState, errorState, skeleton } from "../lib.js";

const STATUS_TEXT = { ok: "complete", warn: "has rejects", fail: "failed", skipped: "not run (sample)", unknown: "no data" };
const REASON_HELP = {
  missing_field: "A required field is absent",
  type_error: "A field has the wrong type",
  invalid_timestamp: "A timestamp cannot be parsed",
  malformed_identifier: "An id has an invalid shape",
  unexpected_structure: "The payload has the wrong shape",
  empty_body: "The response body is empty",
  duplicate_conflict: "Two records disagree on one key",
  invalid_value: "Right type, value not allowed",
};

function stageCard(stage, index) {
  const first = stage.metrics[0];
  return h("div", { class: "stage", role: "listitem", "aria-label": `Stage ${index + 1}: ${stage.label}` },
    h("div", { class: "stage-top" }, h("span", { class: "stage-n" }, `0${index + 1}`),
      h("span", { class: `status ${stage.status}` }, h("i"), STATUS_TEXT[stage.status] || stage.status)),
    h("h3", null, stage.label), h("div", { class: "cap" }, stage.caption),
    h("div", { class: "big" }, first && first.value != null ? fmt.int(first.value) : "n/a"),
    h("div", { class: "big-l" }, first ? first.label : ""),
    h("ul", null, stage.metrics.slice(1).map((m) => h("li", null, h("span", null, m.label), h("b", null, m.value == null ? "n/a" : fmt.int(m.value))))),
    stage.note ? h("p", { class: "note" }, stage.note) : null);
}

function reasonBars(q) {
  const max = Math.max(1, ...q.by_reason.map((r) => r.count));
  return h("div", null, q.by_reason.map((r) => h("div", { class: `rbar${r.count ? "" : " zero"}`, title: REASON_HELP[r.reason] || "" },
    h("span", { class: "mono" }, r.reason), h("span", { class: "track" }, h("span", { style: `width:${(r.count / max) * 100}%` })), h("span", { class: "n" }, r.count))));
}

export function pipelineView(ctx) {
  const root = h("div", { class: "view" },
    h("div", { class: "page-head" }, h("h1", null, "Pipeline")), skeleton(6, 260));
  getJSON("pipeline.json").then((d) => {
    ctx.setBanner(d.is_sample);
    const run = d.run;
    const facts = [
      ["Run", run.id != null ? `#${run.id}` : "no run id"], ["Status", run.status === "sample" ? "sample data" : run.status || "n/a"],
      ["Started", fmt.dateTime(run.started_at)], ["Duration", fmt.duration(run.duration_s)],
      ["Git commit", run.git_commit ? h("span", { class: "mono" }, run.git_commit) : "n/a"],
      ["Config hash", run.config_hash ? h("span", { class: "mono" }, run.config_hash) : "n/a"],
    ];
    const q = d.quarantine, qa = d.quality;
    const qaRan = qa.ran !== false && qa.results.length > 0; // older exports have no "ran" flag
    put(root, 
      h("div", { class: "page-head" }, h("div", null, h("h1", null, "Pipeline", " ", d.is_sample ? sampleTag() : null),
        h("p", { class: "lede" }, "Live APIs, to raw files, to Pydantic validation, to pandas, to PostgreSQL, to the SQL views behind every number here.")),
        h("a", { class: "btn", href: d.repo_url, target: "_blank", rel: "noopener noreferrer" }, "View repository ↗")),
      h("dl", { class: "runbar" }, facts.map(([k, v]) => h("div", null, h("dt", null, k), h("dd", null, v)))),
      d.run.notes && !d.is_sample ? h("p", { class: "meta-line", style: "margin:-6px 0 14px" }, d.run.notes) : null,
      h("div", { class: "flow", role: "list" }, d.stages.map((s, i) => stageCard(s, i))),
      d.sample_note ? h("p", { class: "meta-line", style: "margin:-4px 0 16px" }, d.sample_note) : null,
      h("div", { class: "grid-2" },
        panel({ title: "Quarantine", sub: `${fmt.int(q.total)} record${q.total === 1 ? "" : "s"} set aside this run. Nothing is silently dropped: each row keeps its reason, field path and raw object id.` },
          h("div", null, reasonBars(q), h("p", { class: "meta-line", style: "margin-top:10px" },
            Object.entries(q.by_stage).length ? `By stage: ${Object.entries(q.by_stage).map(([k, v]) => `${k} ${v}`).join(" · ")}` : "No records quarantined."))),
        panel({ title: "Data quality", sub: qaRan ? `${qa.passed} passed, ${qa.failed} failed` : "Not run for this export", aside: null }, qaRan ? h("div", { class: "table-wrap", style: "max-height:none" }, h("table", null,
          h("thead", null, h("tr", null, ["Check", "Table", "Value", "Threshold", "Result"].map((c, i) => h("th", { scope: "col", class: i === 2 || i === 3 ? "r" : "" }, c)))),
          h("tbody", null, qa.results.map((r) => h("tr", { style: "cursor:default" },
            h("td", null, h("span", { class: "mono" }, r.check), h("span", { class: "sub" }, r.dimension)), h("td", { class: "mono" }, r.table || "n/a"),
            h("td", { class: "r" }, r.value == null ? "n/a" : Number(r.value).toLocaleString("en-US", { maximumFractionDigits: 3 })),
            h("td", { class: "r" }, r.threshold == null ? "none" : r.threshold), h("td", null, h("span", { class: `status ${r.passed ? "pass" : "fail"}` }, h("i"), r.passed ? "pass" : "fail"))))))) : h("p", { class: "muted", style: "font-size:13px;max-width:60ch" }, "Quality rules are defined in ", h("span", { class: "mono" }, "src/pipeline/quality/rules.py"), " but were not run for this export."))),
      h("div", { class: "grid-2", style: "margin-top:16px" },
        panel({ title: "Quarantined records", sub: "Newest first, trimmed", flush: true }, q.samples.length ? h("div", { class: "table-wrap", style: "max-height:360px" }, h("table", null,
          h("thead", null, h("tr", null, ["Reason", "Field path", "Raw object", "Message"].map((c) => h("th", { scope: "col" }, c)))),
          h("tbody", null, q.samples.map((r) => h("tr", { style: "cursor:default" }, h("td", { class: "mono" }, r.reason), h("td", { class: "mono" }, r.field_path || "(root)"),
            h("td", { class: "num" }, r.raw_object_id == null ? "n/a" : r.raw_object_id), h("td", { style: "white-space:normal;min-width:240px;max-width:52ch;line-height:1.4;padding-top:6px;padding-bottom:6px" }, r.message || "")))))) : emptyState("Nothing quarantined", "Every response in this run passed validation.")),
        h("div", { class: "stack" },
          panel({ title: "Sources", sub: `Responses saved by the extract stage, ${d.sources_scope || "all runs"}` }, d.sources.length ? h("div", { class: "table-wrap", style: "max-height:none" }, h("table", null,
            h("thead", null, h("tr", null, ["Source", "Responses", "HTTP 200", "404", "Other"].map((c, i) => h("th", { scope: "col", class: i ? "r" : "" }, c)))),
            h("tbody", null, d.sources.map((r) => h("tr", { style: "cursor:default" }, h("td", { class: "mono" }, r.source), h("td", { class: "r" }, fmt.int(r.responses)), h("td", { class: "r" }, fmt.int(r.ok)),
              h("td", { class: "r" }, fmt.int(r.not_found)), h("td", { class: "r" }, fmt.int(r.other_status))))))) : emptyState("No responses", "No raw objects have been registered yet.")),
          panel({ title: "Run history", flush: true }, d.recent_runs.length ? h("div", null, d.recent_runs.map((r) => h("div", { class: "dep-row" },
            h("span", { class: "mono" }, `#${r.id}`), h("span", { class: `status ${r.status === "succeeded" ? "ok" : r.status === "failed" || r.status === "interrupted" ? "fail" : "warn"}`, title: r.status === "interrupted" ? "Still marked running in the database, but it started more than 6 hours ago" : null }, h("i"), r.status),
            h("span", { class: "dep-meta muted" }, fmt.dateTime(r.started_at))))) : emptyState("No earlier runs", "Run history appears once the pipeline has run against a database.")))),
      d.tables.length ? h("div", { style: "margin-top:16px" }, panel({ title: d.is_sample ? "Transform output" : "Rows in the database", sub: d.is_sample ? "Rows in the frames, before loading. Nothing is stored in a database in sample mode." : "Current table sizes", className: "tbl-panel" }, h("div", { class: "chips" }, d.tables.map((t) => h("span", { class: "chip" }, `${t.name} ${fmt.int(t.rows)}`))))) : null);
  }).catch((err) => put(root, h("div", { class: "page-head" }, h("h1", null, "Pipeline")), errorState(err, "the pipeline summary")));
  return root;
}
