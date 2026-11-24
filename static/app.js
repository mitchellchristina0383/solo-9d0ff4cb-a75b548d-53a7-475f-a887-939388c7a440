/* 双线路 VPN 网段重叠核查 —— 前端逻辑（无框架、无依赖）。 */
"use strict";

const $ = (id) => document.getElementById(id);

const PRESETS = {
  // ① 回程被更长前缀接走：B1 的别名 /25 落在 A1 别名 /24 内，回程截胡
  hijack: {
    segA: "10.0.0.0/24   # A 分支待接入整段",
    ruleA: "A1: 10.0.0.0/24 -> 172.16.0.0/24",
    segB: "10.0.99.128/25  # B 分支待接入（与 A 原网段重叠的是别名侧）",
    ruleB: "B1: 10.0.99.128/25 -> 172.16.0.128/25  # 别名与 A1 重叠且前缀更长，回程被它接走",
  },
  // ② 两线同一别名前缀同长并列
  ambiguity: {
    segA: "10.0.0.0/24",
    ruleA: "A1: 10.0.0.0/24 -> 172.16.0.0/24",
    segB: "10.0.0.0/24",
    ruleB: "B1: 10.0.0.0/24 -> 172.16.0.0/24",
  },
  // ③ 干净基线：别名不重叠，无冲突无歧义
  clean: {
    segA: "10.0.0.0/24\n10.1.0.0/24",
    ruleA:
      "A1: 10.0.0.0/24 -> 172.16.0.0/24\n" +
      "A2: 10.1.0.0/24 -> 172.16.1.0/24",
    segB: "10.0.0.0/24",
    ruleB: "B1: 10.0.0.0/24 -> 172.17.0.0/24",
  },
};

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function ruleId(r) {
  return `${r.line}#${r.index}${r.name ? `（${r.name}）` : ""}`;
}

function rangesHtml(ranges) {
  return ranges
    .map((r) => `<code class="cidr">${esc(r.label)}</code>
                 <span class="size">${r.size} 个地址</span>`)
    .join("<br>");
}

function refsHtml(refs) {
  return refs.map((r) => `<code>${esc(r.cidr || r.original || "")}</code>`).join(" ");
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => t.classList.add("hidden"), 2500);
}

async function runCheck() {
  const body = {
    A: { segments_text: $("segA").value, rules_text: $("ruleA").value },
    B: { segments_text: $("segB").value, rules_text: $("ruleB").value },
  };
  let resp;
  try {
    resp = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    toast("请求失败：" + e);
    return;
  }
  const data = await resp.json();
  if (!resp.ok || !data.ok) {
    showErrors(data.validation_errors || [{ message: data.error || "核查失败" }]);
    return;
  }
  $("cardErrors").classList.add("hidden");
  render(data);
}

function showErrors(errors) {
  const card = $("cardErrors");
  card.classList.remove("hidden");
  $("errorList").innerHTML = errors
    .map((e) => `<li><span class="line-tag">${esc(e.line || "全局")}</span>
                 <span class="field-tag">${esc(e.field || "")}</span>
                 ${esc(e.message)}</li>`)
    .join("");
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function render(data) {
  renderSummary(data);
  renderMapping(data);
  renderFindings(data.findings);
}

function renderSummary(data) {
  const s = data.summary;
  const c = s.finding_counts;
  const items = [
    { label: "待核查地址总数", value: s.address_total, cls: "neutral" },
    { label: "去程已映射", value: s.address_mapped, cls: "ok" },
    { label: "去程未映射", value: s.address_unmapped, cls: c.unmapped_outbound ? "bad" : "ok" },
    { label: "别名冲突地址", value: s.alias_conflict_addresses, cls: c.alias_conflicts ? "bad" : "ok" },
    { label: "回程歧义地址", value: s.return_ambiguity_addresses, cls: c.return_ambiguity ? "bad" : "ok" },
    { label: "回错线路地址", value: s.wrong_line_addresses, cls: c.wrong_line ? "bad" : "ok" },
    { label: "回错地址数", value: s.wrong_address_addresses, cls: c.wrong_address ? "bad" : "ok" },
  ];
  $("summary").innerHTML = items
    .map((i) => `<div class="stat ${i.cls}">
                   <div class="stat-num">${i.value.toLocaleString()}</div>
                   <div class="stat-label">${i.label}</div></div>`)
    .join("");

  const lineBits = ["A", "B"].map((k) => {
    const st = data.lines[k];
    return `<div class="line-stat line-${k.toLowerCase()}">
      <strong>线路 ${k}</strong>：${st.segment_count} 个网段 / ${st.rule_count} 条规则，
      共 ${st.address_total} 地址（已映射 ${st.address_mapped}，未映射 ${st.address_unmapped}）
    </div>`;
  }).join("");
  $("summary").insertAdjacentHTML("beforeend", `<div class="line-stats">${lineBits}</div>`);
}

function renderMapping(data) {
  const rows = data.outbound_mapping;
  $("cardMapping").classList.toggle("hidden", rows.length === 0);
  $("mappingRows").innerHTML = rows
    .map((m) => `<tr>
      <td><span class="badge badge-${m.line.toLowerCase()}">${m.line}</span></td>
      <td><code>${esc(ruleId(m.rule))}</code><br>
          <small class="hint">${esc(m.rule.original)} → ${esc(m.rule.alias)}</small></td>
      <td>${rangesHtml([m.original_range])}</td>
      <td>${rangesHtml([m.alias_range])}</td>
    </tr>`)
    .join("");
}

const FINDING_META = [
  {
    key: "unmapped_outbound", title: "① 去程未映射（本线路无原前缀命中）",
    bad: true,
    body: (e) => `
      <div class="meta-row"><span class="line-tag">线路 ${esc(e.line)}</span>
        涉及网段：${refsHtml(e.segments)}</div>
      <div class="range-row">未映射地址范围：<br>${rangesHtml(e.ranges)}</div>`,
  },
  {
    key: "alias_conflicts", title: "② 别名冲突（一个别名对应多个来源）",
    bad: true,
    body: (e) => `
      <div class="range-row">冲突别名范围：<br>${rangesHtml(e.ranges)}</div>
      <div class="meta-row">来源（${e.sources.length} 个）：
        <ul class="sub-list">${e.sources
          .map((s) => `<li><span class="line-tag">线路 ${esc(s.line)}</span>
            规则 <code>${esc(ruleId(s.rule))}</code>
            （${esc(s.rule.original)} → ${esc(s.rule.alias)}），
            来源原地址 <code>${esc(s.original_range.label)}</code></li>`)
          .join("")}</ul>
      </div>`,
  },
  {
    key: "return_ambiguity", title: "③ 回程歧义（别名最长匹配同长并列）",
    bad: true,
    body: (e) => `
      <div class="range-row">歧义别名范围：<br>${rangesHtml(e.ranges)}</div>
      <div class="meta-row">并列命中规则：
        ${e.tied_rules.map((r) => `<span class="line-tag">线路 ${esc(r.line)}</span>
          <code>${esc(ruleId(r))}</code>（别名 ${esc(r.alias)}）`).join("，")}
      </div>`,
  },
  {
    key: "wrong_line", title: "④ 回错线路（命中规则在另一条线路）",
    bad: true,
    body: (e) => `
      <div class="range-row">别名范围：<br>${rangesHtml(e.ranges)}</div>
      <div class="meta-row">
        来源：<span class="line-tag">线路 ${esc(e.source_line)}</span>
        规则 <code>${esc(ruleId(e.source_rule))}</code><br>
        实际回程到：<span class="line-tag">线路 ${esc(e.actual_line)}</span>
        规则 <code>${esc(ruleId(e.winner_rule))}</code>
        （${esc(e.winner_rule.alias)} 前缀更长）<br>
        本应回到原地址：<code>${esc(e.expected_original_range.label)}</code>
      </div>`,
  },
  {
    key: "wrong_address", title: "⑤ 回错地址（反算原地址与来源不一致）",
    bad: true,
    body: (e) => `
      <div class="range-row">别名范围：<br>${rangesHtml(e.ranges)}</div>
      <div class="meta-row">
        来源：<span class="line-tag">线路 ${esc(e.source_line)}</span>
        规则 <code>${esc(ruleId(e.source_rule))}</code><br>
        回程命中：<span class="line-tag">线路 ${esc(e.winner_rule.line)}</span>
        规则 <code>${esc(ruleId(e.winner_rule))}</code><br>
        应到原地址：<code>${esc(e.expected_original_range.label)}</code><br>
        实际被送到：<code>${esc(e.actual_destination_range.label)}</code>
      </div>`,
  },
];

function renderFindings(findings) {
  const stack = $("findingsStack");
  stack.innerHTML = "";
  let total = 0;
  for (const meta of FINDING_META) {
    const entries = findings[meta.key] || [];
    total += entries.length;
    const card = document.createElement("div");
    card.className = "card finding-card" + (entries.length ? " finding-bad" : " finding-ok");
    card.innerHTML = `<h2>${meta.title}
        <span class="count-pill ${entries.length ? "pill-bad" : "pill-ok"}">
          ${entries.length} 组</span></h2>
      ${entries.length
        ? entries.map(meta.body).join('<hr class="sep">')
        : '<p class="hint">✔ 未发现此类问题。</p>'}`;
    stack.appendChild(card);
  }
  if (total === 0) toast("核查通过：未发现任何冲突或错路");
}

// ---- 事件绑定 ----
$("btnCheck").addEventListener("click", runCheck);
$("btnClear").addEventListener("click", () => {
  ["segA", "ruleA", "segB", "ruleB"].forEach((id) => ($(id).value = ""));
});
document.querySelectorAll("[data-preset]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const p = PRESETS[btn.dataset.preset];
    $("segA").value = p.segA;
    $("ruleA").value = p.ruleA;
    $("segB").value = p.segB;
    $("ruleB").value = p.ruleB;
    runCheck();
  });
});
