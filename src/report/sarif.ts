import type { Finding, Severity, FindingStatus } from "../types.js";
import type { ReportMeta } from "./json.js";
import { riskOf } from "./summary.js";

/** SARIF level per finding status. */
const LEVEL: Record<FindingStatus, "error" | "warning" | "note" | "none"> = {
  fail: "error",
  warn: "warning",
  error: "note",
  pass: "none",
  skipped: "none",
};

/** GitHub code scanning security-severity score (0–10). */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

/**
 * SARIF 2.1.0 report — ingestible by GitHub code scanning, Azure DevOps, and
 * most security platforms. Only issues (fail/warn/error) are emitted as
 * results.
 */
export function renderSarif(findings: Finding[], meta: ReportMeta): string {
  const reported = findings.filter((f) => LEVEL[f.status] !== "none");

  // Rules deduplicated by id.
  const rulesById = new Map<string, Finding>();
  for (const f of reported) {
    if (!rulesById.has(f.id)) rulesById.set(f.id, f);
  }

  const rules = [...rulesById.values()].map((f) => ({
    id: f.id,
    name: f.title.replace(/[^A-Za-z0-9]/g, "").slice(0, 60) || f.id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.detail },
    helpUri: f.references?.[0],
    help: {
      text: f.recommendation ?? f.detail,
    },
    properties: {
      "security-severity": SECURITY_SEVERITY[f.severity],
      tags: ["security", f.category],
    },
  }));

  const results = reported.map((f) => {
    const r = riskOf(f);
    return {
      ruleId: f.id,
      level: LEVEL[f.status],
      message: {
        text: f.recommendation ? `${f.detail} ${f.recommendation}` : f.detail,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.resource ?? meta.baseUrl },
          },
        },
      ],
      properties: {
        severity: f.severity,
        category: f.category,
        risk: r.score,
        "risk-level": r.level,
      },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "keycloak-security-audit",
            informationUri: "https://github.com/keycloak/keycloak",
            version: "0.1.0",
            rules,
          },
        },
        results,
        properties: { target: meta.baseUrl, realm: meta.realm, date: meta.date },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
