import type { Finding } from "../types.js";
import { summarize, sortFindings, riskOf } from "./summary.js";

export interface ReportMeta {
  baseUrl: string;
  realm: string;
  date: string;
  mode: string;
}

/** Structured JSON output, suitable for ingestion by a SIEM or a script. */
export function renderJson(findings: Finding[], meta: ReportMeta): string {
  return JSON.stringify(
    {
      tool: "keycloak-security-audit",
      version: "0.1.0",
      meta,
      summary: summarize(findings),
      findings: sortFindings(findings).map((f) => ({ ...f, risk: riskOf(f) })),
    },
    null,
    2,
  );
}
