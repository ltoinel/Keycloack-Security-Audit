import type { Check, Finding, Severity } from "../../types.js";
import { finding } from "../helpers.js";
import { categoryOf } from "../registry.js";
import { resolveKeycloakVersion } from "./detectVersion.js";
import { satisfiesRange } from "./semver.js";

/** Keycloak Maven packages monitored via the GitHub advisories API. */
const KC_PACKAGES = [
  "org.keycloak:keycloak-core",
  "org.keycloak:keycloak-services",
  "org.keycloak:keycloak-server-spi",
  "org.keycloak:keycloak-quarkus-server",
  "org.keycloak:keycloak-saml-core",
];

interface GhVulnerability {
  package?: { ecosystem?: string; name?: string };
  vulnerable_version_range?: string;
  first_patched_version?: string | null;
}
interface GhAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  summary?: string;
  severity?: string;
  html_url?: string;
  vulnerabilities?: GhVulnerability[];
}

/** Extracts the `rel="next"` URL from a GitHub Link header, or null. */
function parseNextLink(link: string | null): string | null {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (m) return m[1];
  }
  return null;
}

function apiError(resource: string, detail: string): Finding {
  return finding("cve.api-error", {
    resource,
    severity: "info",
    status: "error",
    detail,
  });
}

function mapSeverity(s: string | undefined): Severity {
  switch ((s ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "medium";
  }
}

export const cveCheck: Check = {
  name: "cve",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const CAT = categoryOf("cve.clean", "CVE / Known vulnerabilities");
    const version = await resolveKeycloakVersion(ctx);
    if (!version) {
      return [
        finding("cve.no-version", {
          resource: ctx.baseUrl,
          severity: "info",
          status: "skipped",
          detail:
            "Version not detected: unable to correlate against advisories. Provide it with --kc-version (or KC_VERSION) to enable this check.",
        }),
      ];
    }

    const firstUrl = `https://api.github.com/advisories?ecosystem=maven&affects=${encodeURIComponent(
      KC_PACKAGES.join(","),
    )}&per_page=100`;

    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "User-Agent": "keycloak-security-audit",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (process.env.GITHUB_TOKEN) {
      headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    // Pagination via the Link header (rel="next"), with a safety cap.
    const MAX_PAGES = 15;
    const advisories: GhAdvisory[] = [];
    let next: string | null = firstUrl;
    let pages = 0;
    let partial = false;

    while (next && pages < MAX_PAGES) {
      let res: Response;
      try {
        res = await fetch(next, { headers });
      } catch (err) {
        if (advisories.length === 0) {
          return [
            apiError(
              firstUrl,
              `GitHub API call failed: ${
                err instanceof Error ? err.message : String(err)
              }.`,
            ),
          ];
        }
        partial = true;
        break;
      }
      if (!res.ok) {
        if (advisories.length === 0) {
          return [
            apiError(
              firstUrl,
              `GitHub advisories API unavailable (HTTP ${res.status}). Rate limit? Set GITHUB_TOKEN.`,
            ),
          ];
        }
        partial = true; // use the pages already fetched
        break;
      }
      advisories.push(...((await res.json()) as GhAdvisory[]));
      pages++;
      next = parseNextLink(res.headers.get("link"));
    }
    if (next && pages >= MAX_PAGES) partial = true;

    const out: Finding[] = [];
    for (const adv of advisories) {
      const hit = (adv.vulnerabilities ?? []).find((v) => {
        const name = v.package?.name ?? "";
        if (!name.includes("keycloak")) return false;
        if (!v.vulnerable_version_range) return false;
        return satisfiesRange(version, v.vulnerable_version_range);
      });
      if (!hit) continue;

      const id = adv.cve_id ?? adv.ghsa_id;
      out.push(
        finding(`cve.${adv.ghsa_id}`, {
          title: `${id} — ${adv.summary ?? "Keycloak vulnerability"}`,
          category: CAT,
          resource: `keycloak ${version}`,
          severity: mapSeverity(adv.severity),
          status: "fail",
          detail: `Version ${version} is within the vulnerable range "${hit.vulnerable_version_range}" (${hit.package?.name}).`,
          recommendation: hit.first_patched_version
            ? `Upgrade to ${hit.first_patched_version} or later.`
            : "Apply the fix indicated in the advisory.",
          references: [
            adv.html_url ?? `https://github.com/advisories/${adv.ghsa_id}`,
          ],
        }),
      );
    }

    if (out.length === 0) {
      out.push(
        finding("cve.clean", {
          resource: `keycloak ${version}`,
          severity: "info",
          status: "pass",
          detail: `No known GitHub advisory matches version ${version} (${advisories.length} advisory(ies) reviewed across ${pages} page(s)${
            partial ? ", PARTIAL analysis — see recommendation" : ""
          }).`,
          ...(partial
            ? {
                recommendation:
                  "Incomplete list (rate limit or pagination cap reached): set GITHUB_TOKEN and cross-check with the NVD / Keycloak Release Notes.",
              }
            : {}),
        }),
      );
    }

    return out;
  },
};
