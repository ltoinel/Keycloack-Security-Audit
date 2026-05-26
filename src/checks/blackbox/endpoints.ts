import type { Check, Finding, Severity } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

/** Keycloak (Quarkus) management listener port — health/metrics by default. */
const MGMT_PORT = 9000;

interface SensitiveEndpoint {
  path: string;
  id: string;
  severity: Severity;
}

/** health and metrics are served on the management listener (port 9000). */
const MGMT_ENDPOINTS: SensitiveEndpoint[] = [
  { path: "/metrics", id: "endpoint.metrics", severity: "medium" },
  { path: "/health", id: "endpoint.health", severity: "low" },
];

/** Origins to probe: main port + management listener (9000) over https/http. */
function candidateOrigins(baseUrl: string): string[] {
  const u = new URL(baseUrl);
  return [
    baseUrl,
    `https://${u.hostname}:${MGMT_PORT}`,
    `http://${u.hostname}:${MGMT_PORT}`,
  ];
}

/**
 * Confirms a response is genuinely the Keycloak admin console SPA — not a
 * redirect, an SSO/login portal or a generic page. Across versions the console
 * bootstraps its assets from `/resources/<version>/admin/...`.
 */
export function looksLikeAdminConsole(body: string, contentType: string): boolean {
  const isHtml = contentType.includes("text/html") || /<html/i.test(body);
  const hasMarker =
    /\/resources\/[^"']+\/admin/i.test(body) ||
    /<title>[^<]*keycloak/i.test(body) ||
    /administration console/i.test(body) ||
    /id=["']?keycloak["']?/i.test(body);
  return isHtml && hasMarker;
}

export const endpointsCheck: Check = {
  name: "endpoints",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const dispatcher = dispatcherFor(ctx.tlsVerify);
    const out: Finding[] = [];
    const origins = candidateOrigins(ctx.baseUrl);

    for (const ep of MGMT_ENDPOINTS) {
      let exposedAt: string | null = null;
      for (const origin of origins) {
        const res = await safeFetch(`${origin}${ep.path}`, {
          redirect: "manual",
          dispatcher,
        });
        if (!("error" in res) && res.status === 200) {
          exposedAt = origin;
          break;
        }
      }
      out.push(
        finding(ep.id, {
          resource: exposedAt ? `${exposedAt}${ep.path}` : ctx.baseUrl,
          severity: ep.severity,
          status: exposedAt ? "warn" : "pass",
          detail: exposedAt
            ? `Reachable (HTTP 200) at ${exposedAt}${ep.path}.`
            : `Not reachable from the scanner (neither the main port nor management ${MGMT_PORT}).`,
        }),
      );
    }

    // --- Admin console: confirm the real console is served (not a redirect) ---
    const consoleUrl = `${ctx.baseUrl}/admin/master/console/`;
    const res = await safeFetch(consoleUrl, { redirect: "manual", dispatcher });

    let consoleStatus: "warn" | "pass" = "pass";
    let consoleDetail: string;
    if ("error" in res) {
      consoleDetail = "Admin console not reachable from the scanner.";
    } else if (res.status >= 300 && res.status < 400) {
      // A redirect is not the console itself (HTTP->HTTPS, SSO portal, proxy...).
      const loc = res.headers.get("location") ?? "(unknown)";
      consoleDetail = `Path returns an HTTP ${res.status} redirect to ${loc} — not the admin console itself.`;
    } else if (
      res.status === 200 &&
      looksLikeAdminConsole(res.body, res.headers.get("content-type") ?? "")
    ) {
      consoleStatus = "warn";
      consoleDetail =
        "The admin console is served and publicly reachable. Not blocking if protected by authentication + MFA, but reducing its exposure surface is recommended.";
    } else {
      consoleDetail = `Path returns HTTP ${res.status} but the response is not the admin console page.`;
    }
    out.push(
      finding("endpoint.admin-console", {
        resource: consoleUrl,
        severity: "info",
        status: consoleStatus,
        detail: consoleDetail,
      }),
    );

    return out;
  },
};
