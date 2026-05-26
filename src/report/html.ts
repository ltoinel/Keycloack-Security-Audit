import type { Finding, Severity, FindingStatus } from "../types.js";
import type { RiskLevel } from "./summary.js";
import { summarize, sortFindings, RISK_ORDER, riskOf } from "./summary.js";

/** Severity palette (label + accent color). */
const SEV: Record<Severity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "#dc2626" },
  high: { label: "High", color: "#ea580c" },
  medium: { label: "Medium", color: "#d97706" },
  low: { label: "Low", color: "#2563eb" },
  info: { label: "Info", color: "#64748b" },
};

/** Status palette (label + accent color). */
const STATUS: Record<FindingStatus, { label: string; color: string }> = {
  fail: { label: "Fail", color: "#dc2626" },
  warn: { label: "Warn", color: "#d97706" },
  pass: { label: "Pass", color: "#16a34a" },
  skipped: { label: "Skipped", color: "#94a3b8" },
  error: { label: "Error", color: "#64748b" },
};

/** Risk-level palette (label + accent color). */
const RISK: Record<RiskLevel, { label: string; color: string }> = {
  critical: { label: "Critical", color: "#b91c1c" },
  high: { label: "High", color: "#ea580c" },
  medium: { label: "Medium", color: "#d97706" },
  low: { label: "Low", color: "#2563eb" },
  none: { label: "None", color: "#94a3b8" },
};

/** Human label for the likelihood factor derived from a finding's status. */
const LIKELIHOOD_LABEL: Record<FindingStatus, string> = {
  fail: "confirmed",
  warn: "potential",
  pass: "n/a",
  skipped: "n/a",
  error: "n/a",
};

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Short, human label for a reference link (its host name when parseable). */
function refLabel(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "reference";
  }
}

export function renderHtml(
  findings: Finding[],
  meta: { baseUrl: string; realm: string; date: string; mode: string },
): string {
  const s = summarize(findings);
  const sorted = sortFindings(findings);

  const scoreColor =
    s.score >= 85 ? "#16a34a" : s.score >= 60 ? "#d97706" : "#dc2626";
  const scoreLabel =
    s.score >= 85
      ? "Strong posture"
      : s.score >= 60
        ? "Needs attention"
        : "At risk";

  // Donut gauge geometry.
  const R = 54;
  const CIRC = 2 * Math.PI * R;
  const offset = CIRC * (1 - s.score / 100);

  // Findings grouped by category, preserving the sorted order.
  const byCat = new Map<string, Finding[]>();
  for (const f of sorted) {
    if (!byCat.has(f.category)) byCat.set(f.category, []);
    byCat.get(f.category)!.push(f);
  }

  // Risk-level distribution (weighted: impact × likelihood).
  const riskLevels = RISK_ORDER.filter((l) => l !== "none");
  const totalRisked = riskLevels.reduce((acc, l) => acc + s.byRisk[l], 0);
  const distSegments = riskLevels
    .filter((l) => s.byRisk[l] > 0)
    .map((l) => {
      const pct = ((s.byRisk[l] / totalRisked) * 100).toFixed(2);
      return `<span class="bar-seg" style="width:${pct}%;background:${RISK[l].color}" title="${RISK[l].label} risk: ${s.byRisk[l]}"></span>`;
    })
    .join("");
  const distLegend = riskLevels
    .filter((l) => s.byRisk[l] > 0)
    .map(
      (l) =>
        `<span class="legend-item"><span class="dot" style="background:${RISK[l].color}"></span>${RISK[l].label}<b>${s.byRisk[l]}</b></span>`,
    )
    .join("");

  // Top risks: the highest-scoring findings, ranked.
  const topRisks = sorted.filter((f) => riskOf(f).score > 0).slice(0, 5);
  const topRisksHtml = topRisks
    .map((f, i) => {
      const r = riskOf(f);
      return `<div class="tr-item" style="--c:${RISK[r.level].color}">
          <span class="tr-rank">${i + 1}</span>
          <span class="tr-main"><span class="tr-title">${esc(f.title)}</span><span class="tr-cat">${esc(f.category)}</span></span>
          <span class="tr-badge" style="--c:${RISK[r.level].color}">${RISK[r.level].label}</span>
          <span class="tr-score" style="--c:${RISK[r.level].color}">${r.score}</span>
        </div>`;
    })
    .join("");

  // Top filter chips with live counts.
  const otherCount = s.byStatus.skipped + s.byStatus.error;
  const chips = [
    { f: "all", label: "All", count: s.total },
    { f: "issues", label: "Issues", count: s.byStatus.fail + s.byStatus.warn },
    { f: "pass", label: "Passed", count: s.byStatus.pass },
    ...(otherCount > 0
      ? [{ f: "other", label: "Other", count: otherCount }]
      : []),
  ]
    .map(
      (c, i) =>
        `<button class="chip${i === 0 ? " active" : ""}" data-filter="${c.f}">${c.label}<span class="chip-count">${c.count}</span></button>`,
    )
    .join("");

  // Stat cards (status breakdown).
  const stats = [
    { label: "Failures", value: s.byStatus.fail, color: STATUS.fail.color },
    { label: "Warnings", value: s.byStatus.warn, color: STATUS.warn.color },
    { label: "Passed", value: s.byStatus.pass, color: STATUS.pass.color },
    {
      label: "Skipped / errors",
      value: s.byStatus.skipped + s.byStatus.error,
      color: STATUS.skipped.color,
    },
  ]
    .map(
      (st) =>
        `<div class="stat"><span class="stat-val" style="color:${st.color}">${st.value}</span><span class="stat-lbl">${st.label}</span></div>`,
    )
    .join("");

  const sections = [...byCat.entries()]
    .map(([cat, items]) => {
      const cards = items
        .map((f) => {
          const st = STATUS[f.status];
          const r = riskOf(f);
          const showRisk = r.score > 0;
          return `
        <article class="finding" data-status="${f.status}" data-risk="${r.score}" style="--accent:${st.color}">
          <div class="f-top">
            <span class="badge" style="--c:${st.color}">${st.label}</span>
            <h3 class="f-title">${esc(f.title)}</h3>
            ${showRisk ? `<span class="risk" style="--c:${RISK[r.level].color}">${RISK[r.level].label} risk · ${r.score}</span>` : ""}
          </div>
          ${f.resource ? `<div class="f-res"><code>${esc(f.resource)}</code></div>` : ""}
          <p class="f-detail">${esc(f.detail)}</p>
          ${showRisk ? `<div class="f-riskmeta">Impact <b>${SEV[f.severity].label}</b> × Likelihood <b>${LIKELIHOOD_LABEL[f.status]}</b> = <b>${r.score}</b> risk pts</div>` : ""}
          ${
            f.recommendation && f.status !== "pass"
              ? `<div class="f-reco"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 18h6m-5 3h4M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.2 1 2V17h6v-.3c0-.8.4-1.5 1-2A7 7 0 0 0 12 2Z"/></svg><span>${esc(f.recommendation)}</span></div>`
              : ""
          }
          ${
            f.references?.length
              ? `<div class="f-refs">${f.references
                  .map(
                    (r) =>
                      `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(refLabel(r))}<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg></a>`,
                  )
                  .join("")}</div>`
              : ""
          }
        </article>`;
        })
        .join("");
      return `<section class="cat">
        <div class="cat-head"><h2>${esc(cat)}</h2><span class="cat-count">${items.length}</span></div>
        <div class="cards">${cards}</div>
      </section>`;
    })
    .join("");

  const prettyDate = meta.date.replace("T", " ").replace(/\..*/, "") + " UTC";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keycloak Security Audit — ${esc(meta.realm)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..800&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #eceef3;
    --surface: #ffffff;
    --surface-2: #f6f7f9;
    --ink: #10172a;
    --ink-soft: #44506a;
    --ink-faint: #8b95ab;
    --line: #e3e7ef;
    --brand: #3b48d9;
    --score: ${scoreColor};
    --radius: 16px;
    --shadow: 0 1px 2px rgba(16,23,42,.04), 0 8px 24px -12px rgba(16,23,42,.12);
    --shadow-lift: 0 1px 2px rgba(16,23,42,.05), 0 18px 40px -16px rgba(16,23,42,.22);
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    font-family: "IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--ink);
    background: var(--bg);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }
  code, .mono { font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 0 24px 96px; }

  /* ---- Hero ---------------------------------------------------------- */
  .hero {
    position: relative; overflow: hidden;
    background:
      radial-gradient(120% 140% at 12% -10%, #1c2547 0%, #141b35 42%, #0e1428 100%);
    color: #e8ecf6;
    border-bottom: 1px solid #0c1124;
  }
  .hero::before {
    content: ""; position: absolute; inset: 0;
    background-image:
      linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
    background-size: 34px 34px;
    -webkit-mask-image: radial-gradient(120% 100% at 70% 0%, #000 30%, transparent 78%);
            mask-image: radial-gradient(120% 100% at 70% 0%, #000 30%, transparent 78%);
  }
  .hero::after {
    content: ""; position: absolute; right: -120px; top: -120px;
    width: 380px; height: 380px; border-radius: 50%;
    background: radial-gradient(circle, ${scoreColor}33 0%, transparent 68%);
    filter: blur(8px);
  }
  .hero-inner {
    position: relative; max-width: 1000px; margin: 0 auto; padding: 40px 24px 48px;
    display: flex; gap: 40px; align-items: center; justify-content: space-between; flex-wrap: wrap;
  }
  .brand-row { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; }
  .brand-mark {
    width: 38px; height: 38px; flex: 0 0 auto; border-radius: 10px;
    display: grid; place-items: center;
    background: linear-gradient(150deg, #4654ee, #2a32a8);
    box-shadow: 0 6px 18px -6px #4654eeaa, inset 0 1px 0 rgba(255,255,255,.25);
  }
  .brand-mark svg { width: 20px; height: 20px; fill: none; stroke: #fff; stroke-width: 1.8; }
  .brand-name { font-size: 13px; letter-spacing: .14em; text-transform: uppercase; color: #aab4d4; font-weight: 600; }
  h1 {
    font-family: "Bricolage Grotesque", sans-serif;
    font-weight: 700; font-size: clamp(30px, 4.4vw, 46px); line-height: 1.02;
    margin: 0 0 18px; letter-spacing: -.02em;
    color: #f3f6ff;
  }
  .meta { display: flex; flex-wrap: wrap; gap: 8px; }
  .meta .pill {
    display: inline-flex; align-items: center; gap: 7px;
    background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.1);
    padding: 6px 11px; border-radius: 999px; font-size: 13px; color: #c8d0e6;
  }
  .meta .pill b { color: #fff; font-weight: 600; }
  .meta .pill .k { color: #8b96b8; font-size: 11px; text-transform: uppercase; letter-spacing: .07em; }

  /* ---- Gauge --------------------------------------------------------- */
  .gauge { position: relative; flex: 0 0 auto; width: 188px; height: 188px; }
  .gauge svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .gauge .track { fill: none; stroke: rgba(255,255,255,.1); stroke-width: 13; }
  .gauge .prog {
    fill: none; stroke: var(--score); stroke-width: 13; stroke-linecap: round;
    stroke-dasharray: ${CIRC.toFixed(2)};
    stroke-dashoffset: ${CIRC.toFixed(2)};
    animation: gauge 1.5s cubic-bezier(.22,.8,.24,1) .15s forwards;
    filter: drop-shadow(0 0 8px ${scoreColor}66);
  }
  @keyframes gauge { to { stroke-dashoffset: ${offset.toFixed(2)}; } }
  .gauge-center { position: absolute; inset: 0; display: grid; place-items: center; text-align: center; }
  .gauge-num { font-family: "Bricolage Grotesque", sans-serif; font-size: 52px; font-weight: 700; line-height: 1; color: #fff; }
  .gauge-den { font-size: 13px; color: #97a1c0; margin-top: 2px; }
  .gauge-lbl {
    margin-top: 8px; font-size: 11.5px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
    color: var(--score);
  }

  /* ---- Summary panel ------------------------------------------------- */
  .panel {
    margin-top: -28px; position: relative; z-index: 2;
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 22px 24px;
    display: grid; grid-template-columns: 1.4fr 1fr; gap: 28px;
  }
  .panel h4 { margin: 0 0 12px; font-size: 12px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink-faint); font-weight: 600; }
  .bar { display: flex; height: 13px; border-radius: 999px; overflow: hidden; background: #eef0f5; }
  .bar-seg { height: 100%; }
  .bar-empty { width: 100%; background: linear-gradient(90deg, #16a34a, #22c55e); }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 14px; font-size: 13px; color: var(--ink-soft); }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; }
  .legend-item b { color: var(--ink); font-weight: 600; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; align-content: start; }
  .stat { background: var(--surface-2); border: 1px solid var(--line); border-radius: 11px; padding: 12px 14px; }
  .stat-val { display: block; font-family: "Bricolage Grotesque", sans-serif; font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-lbl { display: block; margin-top: 4px; font-size: 12px; color: var(--ink-soft); }
  .risk-total { display: flex; align-items: baseline; gap: 10px; margin-bottom: 14px; }
  .rt-num { font-family: "Bricolage Grotesque", sans-serif; font-size: 34px; font-weight: 700; line-height: 1; color: var(--ink); }
  .rt-lbl { font-size: 12px; color: var(--ink-soft); line-height: 1.35; }
  .rt-sub { display: block; color: var(--ink-faint); font-size: 11px; }

  /* ---- Top risks ----------------------------------------------------- */
  .toprisks { margin-top: 24px; }
  .toprisks h4 { margin: 0 0 12px; font-size: 12px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink-faint); font-weight: 600; }
  .tr-list { display: flex; flex-direction: column; gap: 8px; }
  .tr-item {
    display: flex; align-items: center; gap: 14px;
    background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
    padding: 11px 16px 11px 12px; box-shadow: var(--shadow);
    border-left: 4px solid var(--c);
  }
  .tr-rank { font-family: "Bricolage Grotesque", sans-serif; font-weight: 700; font-size: 15px; color: var(--ink-faint); width: 18px; text-align: center; flex: 0 0 auto; }
  .tr-main { flex: 1 1 auto; min-width: 0; }
  .tr-title { display: block; font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tr-cat { display: block; font-size: 12px; color: var(--ink-faint); }
  .tr-badge { flex: 0 0 auto; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; color: var(--c); }
  .tr-score { flex: 0 0 auto; font-family: "Bricolage Grotesque", sans-serif; font-weight: 700; font-size: 18px; color: var(--c); min-width: 28px; text-align: right; }

  /* ---- Toolbar ------------------------------------------------------- */
  .toolbar {
    position: sticky; top: 0; z-index: 5; margin: 26px 0 6px;
    display: flex; gap: 8px; flex-wrap: wrap; padding: 12px 0;
    background: linear-gradient(var(--bg) 70%, transparent);
  }
  .chip {
    font: inherit; cursor: pointer; display: inline-flex; align-items: center; gap: 8px;
    background: var(--surface); border: 1px solid var(--line); color: var(--ink-soft);
    padding: 7px 14px; border-radius: 999px; font-size: 13.5px; font-weight: 500;
    transition: all .15s ease;
  }
  .chip:hover { border-color: #c6cde0; color: var(--ink); }
  .chip.active { background: var(--ink); border-color: var(--ink); color: #fff; }
  .chip-count {
    font-size: 12px; font-weight: 600; background: var(--surface-2); color: var(--ink-soft);
    padding: 1px 8px; border-radius: 999px; min-width: 22px; text-align: center;
  }
  .chip.active .chip-count { background: rgba(255,255,255,.18); color: #fff; }

  /* ---- Sections & cards ---------------------------------------------- */
  .cat { margin-top: 30px; }
  .cat-head { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .cat-head h2 {
    font-family: "Bricolage Grotesque", sans-serif; font-weight: 600; font-size: 19px;
    margin: 0; letter-spacing: -.01em;
  }
  .cat-count {
    font-size: 12px; font-weight: 600; color: var(--ink-soft);
    background: var(--surface); border: 1px solid var(--line); border-radius: 999px; padding: 1px 9px;
  }
  .cards { display: flex; flex-direction: column; gap: 12px; }
  .finding {
    position: relative; background: var(--surface); border: 1px solid var(--line);
    border-radius: 14px; padding: 16px 18px 16px 22px; box-shadow: var(--shadow);
    transition: transform .18s ease, box-shadow .18s ease;
    animation: rise .5s ease backwards;
  }
  .finding::before {
    content: ""; position: absolute; left: 0; top: 14px; bottom: 14px; width: 4px;
    border-radius: 0 4px 4px 0; background: var(--accent);
  }
  .finding:hover { transform: translateY(-2px); box-shadow: var(--shadow-lift); }
  .f-top { display: flex; align-items: center; gap: 12px; }
  .badge {
    flex: 0 0 auto; font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
    color: var(--c); background: color-mix(in srgb, var(--c) 12%, white);
    border: 1px solid color-mix(in srgb, var(--c) 28%, white);
    padding: 3px 9px; border-radius: 7px;
  }
  .f-title { font-size: 15.5px; font-weight: 600; margin: 0; flex: 1 1 auto; }
  .sev { flex: 0 0 auto; font-size: 11.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; color: var(--c); }
  .risk {
    flex: 0 0 auto; font-size: 11px; font-weight: 700; letter-spacing: .03em; text-transform: uppercase;
    color: var(--c); background: color-mix(in srgb, var(--c) 12%, white);
    border: 1px solid color-mix(in srgb, var(--c) 28%, white);
    padding: 3px 9px; border-radius: 7px; white-space: nowrap;
  }
  .f-riskmeta { margin-top: 9px; font-size: 12px; color: var(--ink-faint); }
  .f-riskmeta b { color: var(--ink-soft); font-weight: 600; }
  .f-res { margin: 9px 0 0; }
  .f-res code, .f-detail code {
    background: var(--surface-2); border: 1px solid var(--line);
    padding: 2px 7px; border-radius: 6px; font-size: 12.5px; color: var(--ink);
    word-break: break-all;
  }
  .f-detail { color: var(--ink-soft); font-size: 14px; margin: 9px 0 0; }
  .f-reco {
    display: flex; gap: 9px; margin-top: 12px; padding: 11px 13px;
    background: #fff8ec; border: 1px solid #f4e3c1; border-radius: 10px;
    font-size: 13.5px; color: #7a5a13;
  }
  .f-reco svg { width: 17px; height: 17px; flex: 0 0 auto; margin-top: 1px; fill: none; stroke: #c98a16; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }
  .f-refs { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 8px; }
  .f-refs a {
    display: inline-flex; align-items: center; gap: 4px; text-decoration: none;
    font-size: 12.5px; color: var(--brand); font-weight: 500;
    background: color-mix(in srgb, var(--brand) 7%, white);
    border: 1px solid color-mix(in srgb, var(--brand) 18%, white);
    padding: 3px 10px; border-radius: 999px; transition: background .15s ease;
  }
  .f-refs a:hover { background: color-mix(in srgb, var(--brand) 14%, white); }
  .f-refs svg { width: 12px; height: 12px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }

  @keyframes rise { from { opacity: 0; transform: translateY(10px); } }
  .cards .finding:nth-child(1) { animation-delay: .02s; }
  .cards .finding:nth-child(2) { animation-delay: .06s; }
  .cards .finding:nth-child(3) { animation-delay: .1s; }
  .cards .finding:nth-child(4) { animation-delay: .14s; }
  .cards .finding:nth-child(n+5) { animation-delay: .18s; }

  footer {
    margin-top: 48px; padding-top: 22px; border-top: 1px solid var(--line);
    color: var(--ink-faint); font-size: 12.5px; line-height: 1.7;
  }
  footer b { color: var(--ink-soft); font-weight: 600; }

  @media (max-width: 720px) {
    .panel { grid-template-columns: 1fr; gap: 22px; }
    .hero-inner { padding: 32px 24px 40px; }
    .gauge { width: 150px; height: 150px; }
    .gauge-num { font-size: 42px; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, ::before, ::after { animation: none !important; transition: none !important; }
    .gauge .prog { stroke-dashoffset: ${offset.toFixed(2)}; }
  }
  @media print {
    body { background: #fff; }
    .toolbar { display: none; }
    .finding, .panel { box-shadow: none; break-inside: avoid; }
    .hero::after { display: none; }
  }
</style>
</head>
<body>
  <header class="hero">
    <div class="hero-inner">
      <div class="hero-text">
        <div class="brand-row">
          <span class="brand-mark"><svg viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 5 3.4 7.8 8 9 4.6-1.2 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg></span>
          <span class="brand-name">Keycloak Security Audit</span>
        </div>
        <h1>Security Audit Report</h1>
        <div class="meta">
          <span class="pill"><span class="k">Target</span><b>${esc(meta.baseUrl)}</b></span>
          <span class="pill"><span class="k">Realm</span><b>${esc(meta.realm)}</b></span>
          <span class="pill"><span class="k">Scope</span><b>${esc(meta.mode)}</b></span>
          <span class="pill"><span class="k">Date</span><b>${esc(prettyDate)}</b></span>
        </div>
      </div>
      <div class="gauge">
        <svg viewBox="0 0 140 140">
          <circle class="track" cx="70" cy="70" r="${R}"></circle>
          <circle class="prog" cx="70" cy="70" r="${R}"></circle>
        </svg>
        <div class="gauge-center">
          <div>
            <div class="gauge-num">${s.score}</div>
            <div class="gauge-den">out of 100</div>
            <div class="gauge-lbl">${scoreLabel}</div>
          </div>
        </div>
      </div>
    </div>
  </header>

  <div class="wrap">
    <div class="panel">
      <div>
        <h4>Risk exposure</h4>
        <div class="risk-total"><span class="rt-num">${s.risk}</span><span class="rt-lbl">weighted risk points<span class="rt-sub">impact × likelihood · score = 100 − risk</span></span></div>
        <div class="bar">${distSegments || '<span class="bar-empty"></span>'}</div>
        <div class="legend">${distLegend || '<span class="legend-item"><span class="dot" style="background:#16a34a"></span>No risk detected</span>'}</div>
      </div>
      <div class="stats">${stats}</div>
    </div>

    ${topRisks.length ? `<section class="toprisks"><h4>Top risks</h4><div class="tr-list">${topRisksHtml}</div></section>` : ""}

    <nav class="toolbar">${chips}</nav>

    ${sections}

    <footer>
      Generated by <b>Keycloak Security Audit</b> · ${esc(prettyDate)}<br>
      Automated, non-exhaustive audit — it does not replace a manual penetration test.
    </footer>
  </div>

<script>
(function () {
  var buttons = document.querySelectorAll(".chip[data-filter]");
  var findings = document.querySelectorAll(".finding");
  var sections = document.querySelectorAll(".cat");
  function apply(filter) {
    findings.forEach(function (el) {
      var st = el.getAttribute("data-status");
      var show =
        filter === "all" ||
        (filter === "issues" && (st === "fail" || st === "warn")) ||
        (filter === "other" && (st === "skipped" || st === "error")) ||
        filter === st;
      el.style.display = show ? "" : "none";
    });
    sections.forEach(function (sec) {
      var visible = 0;
      sec.querySelectorAll(".finding").forEach(function (f) {
        if (f.style.display !== "none") visible++;
      });
      sec.style.display = visible ? "" : "none";
    });
  }
  buttons.forEach(function (b) {
    b.addEventListener("click", function () {
      buttons.forEach(function (x) { x.classList.remove("active"); });
      b.classList.add("active");
      apply(b.getAttribute("data-filter"));
    });
  });
})();
</script>
</body>
</html>`;
}
