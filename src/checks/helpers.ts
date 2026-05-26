import type { Finding, Severity, FindingStatus } from "../types.js";
import { checkMeta } from "./registry.js";

/** Runtime inputs for a finding: severity, status and detail are computed by
 *  the check; title/category/recommendation/references come from the config
 *  (checks.yaml) but can be overridden here for fully-dynamic findings. */
export interface FindingInput {
  status: FindingStatus;
  severity: Severity;
  detail: string;
  resource?: string;
  /** Overrides for dynamic findings (e.g. CVE titles) or contextual advice. */
  title?: string;
  category?: string;
  recommendation?: string;
  references?: string[];
}

/**
 * Builds a Finding, merging runtime values with the configured text for `id`
 * (title, category, recommendation, references). Explicit `recommendation`
 * (including `undefined`) in the input overrides the configured value.
 */
export function finding(id: string, input: FindingInput): Finding {
  const meta = checkMeta(id);
  const recommendation =
    "recommendation" in input ? input.recommendation : meta?.recommendation;
  const f: Finding = {
    id,
    title: input.title ?? meta?.title ?? id,
    category: input.category ?? meta?.category ?? "Other",
    severity: input.severity,
    status: input.status,
    detail: input.detail,
  };
  if (input.resource !== undefined) f.resource = input.resource;
  if (recommendation !== undefined) f.recommendation = recommendation;
  const references = input.references ?? meta?.references;
  if (references !== undefined) f.references = references;
  return f;
}

/** Parses a Keycloak passwordPolicy "length(12) and digits(1)" into a map. */
export function parsePasswordPolicy(policy: string | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!policy) return map;
  for (const part of policy.split(" and ")) {
    const m = part.trim().match(/^([a-zA-Z]+)(?:\(([^)]*)\))?$/);
    if (m) map.set(m[1], m[2] ?? "");
  }
  return map;
}

/** Detects dangerous wildcards in a list of redirect URIs. */
export function dangerousRedirectUris(uris: string[] | undefined): string[] {
  if (!uris) return [];
  return uris.filter((u) => {
    if (u === "*" || u === "/*") return true;
    // subdomain wildcard or overly broad path
    if (/^https?:\/\/\*/.test(u)) return true;
    if (/^http:\/\//.test(u) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(u))
      return true; // non-local http
    return false;
  });
}
