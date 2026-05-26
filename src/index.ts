#!/usr/bin/env node
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { Command } from "commander";
import { loadConfig, hasAdminCredentials } from "./config.js";
import { createAdminApi } from "./keycloak/adminClient.js";
import { allChecks } from "./checks/index.js";
import type { CheckContext, Finding } from "./types.js";
import { renderHtml } from "./report/html.js";
import { renderMarkdown } from "./report/markdown.js";
import { renderJson, type ReportMeta } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";
import { summarize } from "./report/summary.js";

/** Available output formats: extension + renderer. */
const RENDERERS: Record<
  string,
  { ext: string; render: (f: Finding[], m: ReportMeta) => string }
> = {
  html: { ext: "html", render: renderHtml },
  md: { ext: "md", render: renderMarkdown },
  json: { ext: "json", render: renderJson },
  sarif: { ext: "sarif", render: renderSarif },
};

const program = new Command();
program
  .name("keycloak-security-audit")
  .description("Security audit of a Keycloak server (configuration + external tests).")
  .argument("[url]", "Keycloak base URL (alternative to --url or KC_BASE_URL)")
  .option("-u, --url <url>", "Keycloak base URL (otherwise positional argument or KC_BASE_URL)")
  .option("-r, --realm <realm>", "Realm to audit (otherwise KC_REALM)")
  .option(
    "-m, --mode <mode>",
    "Test scope: all | whitebox | blackbox",
    "all",
  )
  .option("-o, --out <dir>", "Output directory for reports", "reports")
  .option(
    "-f, --format <formats>",
    "Comma-separated formats: html,md,json,sarif or all",
    "html,md",
  )
  .option("--no-tls-verify", "Do not verify TLS certificates (internal lab)")
  .option("--fail-on <severity>", "Exit code != 0 if a failure >= severity (critical|high|medium)", "high")
  .option(
    "--kc-version <version>",
    "Keycloak version to audit against for CVE correlation (otherwise KC_VERSION or passive detection)",
  )
  .parse();

const opts = program.opts();

// KC_TLS_VERIFY (.env) must only apply when --no-tls-verify is not passed
// explicitly on the CLI (otherwise the flag default would override the env).
const tlsVerifyOverride =
  program.getOptionValueSource("tlsVerify") === "cli"
    ? (opts.tlsVerify as boolean)
    : undefined;

/** Normalize and validate the requested scope into the internal canonical mode. */
function normalizeMode(raw: string): "all" | "white" | "black" {
  switch (raw.trim().toLowerCase()) {
    case "all":
      return "all";
    case "whitebox":
    case "white":
    case "wb":
      return "white";
    case "blackbox":
    case "black":
    case "bb":
      return "black";
    default:
      console.error(
        `\n❌ Unknown mode: "${raw}". Accepted values: all | whitebox | blackbox.\n`,
      );
      process.exit(2);
  }
}

// URL: positional argument > --url option > KC_BASE_URL (handled in loadConfig).
const positionalUrl = program.args[0];

async function main() {
  const cfg = loadConfig({
    baseUrl: opts.url ?? positionalUrl,
    realm: opts.realm,
    tlsVerify: tlsVerifyOverride,
    version: opts.kcVersion,
  });

  const mode = normalizeMode(opts.mode as string);
  const modeLabel = { all: "all", white: "whitebox", black: "blackbox" }[mode];
  console.log(
    `\n🔎 Keycloak Security Audit — auditing ${cfg.baseUrl} (realm: ${cfg.realm}, scope: ${modeLabel})\n`,
  );
  if (cfg.version) {
    console.log(`📌 Keycloak version (provided): ${cfg.version}\n`);
  }

  const ctx: CheckContext = {
    baseUrl: cfg.baseUrl,
    realm: cfg.realm,
    tlsVerify: cfg.tlsVerify,
    version: cfg.version,
  };

  // --- Admin API authentication (white-box mode) -------------------------
  const wantWhite = mode === "all" || mode === "white";
  if (wantWhite) {
    if (hasAdminCredentials(cfg)) {
      try {
        ctx.admin = await createAdminApi(cfg);
        console.log("✅ Admin API authentication succeeded (white-box checks active).");
      } catch (err) {
        console.warn(
          `⚠️  Admin API unavailable: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        console.warn("   → falling back to black-box only.\n");
      }
    } else {
      console.warn(
        "⚠️  No admin credentials provided: white-box checks will be skipped.\n",
      );
    }
  }

  // --- Check selection and execution -------------------------------------
  const selected = allChecks.filter((c) => {
    if (mode === "white") return c.mode === "white";
    if (mode === "black") return c.mode === "black";
    return true;
  });

  const findings: Finding[] = [];
  for (const check of selected) {
    if (check.mode === "white" && !ctx.admin) {
      findings.push({
        id: `${check.name}.skipped`,
        title: `Check "${check.name}" not executed`,
        category: "White-box",
        severity: "info",
        status: "skipped",
        detail: "Requires Admin API authentication.",
      });
      continue;
    }
    try {
      const res = await check.run(ctx);
      findings.push(...res);
      process.stdout.write(`  • ${check.name}: ${res.length} finding(s)\n`);
    } catch (err) {
      findings.push({
        id: `${check.name}.error`,
        title: `Error in check "${check.name}"`,
        category: "Errors",
        severity: "info",
        status: "error",
        detail: err instanceof Error ? err.message : String(err),
      });
      process.stdout.write(`  ✗ ${check.name}: error\n`);
    }
  }

  // --- Reports -----------------------------------------------------------
  const date = new Date().toISOString();
  const meta: ReportMeta = { baseUrl: cfg.baseUrl, realm: cfg.realm, date, mode };
  const stamp = date.replace(/[:.]/g, "-").slice(0, 19);

  const requested = (opts.format as string)
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .flatMap((s) => (s === "all" ? Object.keys(RENDERERS) : [s]));
  const formats = [...new Set(requested)].filter((f) => {
    if (RENDERERS[f]) return true;
    console.warn(`⚠️  Ignoring unknown format: "${f}".`);
    return false;
  });
  if (formats.length === 0) formats.push("html");

  const outDir = resolve(opts.out as string);
  mkdirSync(outDir, { recursive: true });

  const writtenPaths = formats.map((f) => {
    const { ext, render } = RENDERERS[f];
    const path = resolve(outDir, `keycloak-audit-${cfg.realm}-${stamp}.${ext}`);
    writeFileSync(path, render(findings, meta), "utf8");
    return path;
  });

  // --- Console summary ---------------------------------------------------
  const s = summarize(findings);
  console.log(`\n📊 Score: ${s.score}/100  ·  Risk exposure: ${s.risk} pts`);
  console.log(
    `   Severity — Critical: ${s.bySeverity.critical}  High: ${s.bySeverity.high}  Medium: ${s.bySeverity.medium}  Low: ${s.bySeverity.low}`,
  );
  console.log(
    `   Risk — Critical: ${s.byRisk.critical}  High: ${s.byRisk.high}  Medium: ${s.byRisk.medium}  Low: ${s.byRisk.low}`,
  );
  console.log(`   Pass: ${s.byStatus.pass}  Warn: ${s.byStatus.warn}  Fail: ${s.byStatus.fail}`);
  console.log(`\n📄 Reports:\n${writtenPaths.map((p) => `   ${p}`).join("\n")}\n`);

  // --- Exit code ---------------------------------------------------------
  // The gate only triggers on hard failures (status "fail"), not on "warn",
  // to avoid false CI failures.
  const threshold = opts.failOn as string;
  const order = ["critical", "high", "medium", "low"];
  const thrIdx = order.indexOf(threshold);
  const breach =
    thrIdx >= 0 &&
    order
      .slice(0, thrIdx + 1)
      .some(
        (sev) => s.failuresBySeverity[sev as keyof typeof s.failuresBySeverity] > 0,
      );
  process.exit(breach ? 1 : 0);
}

main().catch((err) => {
  console.error(`\n❌ ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
