import type { Check, Finding, Severity } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

const CAT = "Exposed endpoints";

/** Keycloak (Quarkus) management listener port — health/metrics by default. */
const MGMT_PORT = 9000;

interface SensitiveEndpoint {
  path: string;
  id: string;
  title: string;
  severity: Severity;
  recommendation: string;
}

/** health and metrics are served on the management listener (port 9000). */
const MGMT_ENDPOINTS: SensitiveEndpoint[] = [
  {
    path: "/metrics",
    id: "endpoint.metrics",
    title: "/metrics endpoint exposed",
    severity: "medium",
    recommendation:
      "Keep /metrics on the firewalled management listener (9000), never publicly reachable.",
  },
  {
    path: "/health",
    id: "endpoint.health",
    title: "/health endpoint exposed",
    severity: "low",
    recommendation: "Restrict /health to the internal network / orchestrator.",
  },
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
        finding({
          id: ep.id,
          title: ep.title,
          category: CAT,
          resource: exposedAt ? `${exposedAt}${ep.path}` : ctx.baseUrl,
          severity: ep.severity,
          status: exposedAt ? "warn" : "pass",
          detail: exposedAt
            ? `Reachable (HTTP 200) at ${exposedAt}${ep.path}.`
            : `Not reachable from the scanner (neither the main port nor management ${MGMT_PORT}).`,
          recommendation: ep.recommendation,
        }),
      );
    }

    // --- Admin console: informational -------------------------------------
    // The login page almost always returns 200; this is not a vuln in itself,
    // but reducing its exposure surface is still recommended.
    const consoleUrl = `${ctx.baseUrl}/admin/master/console/`;
    const res = await safeFetch(consoleUrl, { redirect: "manual", dispatcher });
    const reachable =
      !("error" in res) && [200, 301, 302, 303].includes(res.status);
    out.push(
      finding({
        id: "endpoint.admin-console",
        title: "Admin console reachable",
        category: CAT,
        resource: consoleUrl,
        severity: "info",
        status: reachable ? "warn" : "pass",
        detail: reachable
          ? "The admin console is publicly reachable. Not blocking if protected by authentication + MFA, but reducing its exposure surface is recommended."
          : "Admin console not reachable from the scanner.",
        recommendation:
          "Restrict access (IP allowlist / VPN / reverse proxy) in addition to authentication.",
      }),
    );

    return out;
  },
};
