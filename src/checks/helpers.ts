import type { Finding } from "../types.js";

/** Tiny constructor to reduce noise in the checks. */
export function finding(f: Finding): Finding {
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
