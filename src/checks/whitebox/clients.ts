import type { Check, Finding } from "../../types.js";
import { finding, dangerousRedirectUris } from "../helpers.js";

interface ClientRep {
  id: string;
  clientId: string;
  protocol?: string;
  publicClient?: boolean;
  bearerOnly?: boolean;
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  serviceAccountsEnabled?: boolean;
  fullScopeAllowed?: boolean;
  consentRequired?: boolean;
  rootUrl?: string;
  baseUrl?: string;
  adminUrl?: string;
  redirectUris?: string[];
  webOrigins?: string[];
  attributes?: Record<string, string>;
}

/** Built-in clients always present in a realm (and the per-realm `*-realm` clients). */
const DEFAULT_MASTER_CLIENTS = new Set([
  "account",
  "account-console",
  "admin-cli",
  "broker",
  "security-admin-console",
]);

export const clientsCheck: Check = {
  name: "clients",
  mode: "white",
  async run(ctx): Promise<Finding[]> {
    const clients = await ctx.admin!.get<ClientRep[]>(`/${ctx.realm}/clients`);
    const out: Finding[] = [];

    for (const c of clients) {
      const isOidc = (c.protocol ?? "openid-connect") === "openid-connect";
      if (!isOidc || c.bearerOnly) continue;

      // --- Implicit flow (deprecated) ------------------------------------
      if (c.implicitFlowEnabled) {
        out.push(
          finding("client.implicit-flow", {
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Client "${c.clientId}" allows the Implicit Flow (token exposed in the URL).`,
          }),
        );
      }

      // --- Direct Access Grants (ROPC) -----------------------------------
      if (c.directAccessGrantsEnabled) {
        out.push(
          finding("client.direct-access-grants", {
            resource: c.clientId,
            severity: "medium",
            status: "warn",
            detail: `Client "${c.clientId}" allows the password grant (ROPC).`,
          }),
        );
      }

      // --- PKCE on public client -----------------------------------------
      if (c.publicClient && c.standardFlowEnabled) {
        const pkce = c.attributes?.["pkce.code.challenge.method"];
        out.push(
          finding("client.pkce", {
            resource: c.clientId,
            severity: pkce === "S256" ? "low" : "high",
            status: pkce === "S256" ? "pass" : "fail",
            detail:
              pkce === "S256"
                ? `PKCE S256 enforced on "${c.clientId}".`
                : `Public client "${c.clientId}" does not enforce PKCE (method = ${pkce ?? "none"}).`,
          }),
        );
      }

      // --- Service account on public client ------------------------------
      if (c.publicClient && c.serviceAccountsEnabled) {
        out.push(
          finding("client.public-service-account", {
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Client "${c.clientId}" is public AND has a service account (inconsistent / risky).`,
          }),
        );
      }

      // --- Overly broad redirect URIs ------------------------------------
      const bad = dangerousRedirectUris(c.redirectUris);
      if (bad.length > 0) {
        out.push(
          finding("client.redirect-uris", {
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Risky redirect URIs on "${c.clientId}": ${bad.join(", ")}.`,
          }),
        );
      }

      // --- Web Origins (CORS) wildcard -----------------------------------
      if (c.webOrigins?.includes("*")) {
        out.push(
          finding("client.web-origins", {
            resource: c.clientId,
            severity: "medium",
            status: "fail",
            detail: `Client "${c.clientId}" allows all CORS origins (*).`,
          }),
        );
      }

      // --- Full scope (over-privileged tokens) ---------------------------
      if (c.fullScopeAllowed) {
        out.push(
          finding("client.full-scope", {
            resource: c.clientId,
            severity: "medium",
            status: "warn",
            detail: `Client "${c.clientId}" has fullScopeAllowed = true: its tokens carry every realm role.`,
          }),
        );
      }

      // --- Consent for user-facing public clients ------------------------
      if (c.publicClient && c.standardFlowEnabled && c.consentRequired === false) {
        out.push(
          finding("client.consent", {
            resource: c.clientId,
            severity: "low",
            status: "warn",
            detail: `Public client "${c.clientId}" does not require consent (review for third-party clients).`,
          }),
        );
      }

      // --- Non-TLS root/base/admin URL -----------------------------------
      const httpUrls = [c.rootUrl, c.baseUrl, c.adminUrl].filter(
        (u): u is string =>
          !!u &&
          /^http:\/\//i.test(u) &&
          !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(u),
      );
      if (httpUrls.length) {
        out.push(
          finding("client.base-url-http", {
            resource: c.clientId,
            severity: "low",
            status: "warn",
            detail: `Client "${c.clientId}" uses non-TLS URL(s): ${httpUrls.join(", ")}.`,
          }),
        );
      }

      // --- Weak per-client token signing algorithm -----------------------
      const weakAlgs: string[] = [];
      let algNone = false;
      for (const [label, attr] of [
        ["id_token", "id.token.signed.response.alg"],
        ["access_token", "access.token.signed.response.alg"],
      ] as const) {
        const a = c.attributes?.[attr];
        if (!a) continue;
        if (/^none$/i.test(a)) {
          algNone = true;
          weakAlgs.push(`${label}=none`);
        } else if (/^hs/i.test(a)) {
          weakAlgs.push(`${label}=${a}`);
        }
      }
      if (weakAlgs.length) {
        out.push(
          finding("client.token-signing-alg", {
            resource: c.clientId,
            severity: algNone ? "high" : "medium",
            status: algNone ? "fail" : "warn",
            detail: `Client "${c.clientId}" uses a weak token signing algorithm: ${weakAlgs.join(", ")}.`,
          }),
        );
      }
    }

    if (out.length === 0) {
      out.push(
        finding("client.ok", {
          severity: "info",
          status: "pass",
          detail: `${clients.length} client(s) analyzed, no major configuration issue detected.`,
        }),
      );
    }

    // --- Master realm used for application clients (anti-pattern) --------
    if (ctx.realm === "master") {
      const apps = clients.filter(
        (c) =>
          !DEFAULT_MASTER_CLIENTS.has(c.clientId) && !c.clientId.endsWith("-realm"),
      );
      if (apps.length) {
        out.push(
          finding("client.master-realm", {
            resource: "master",
            severity: "medium",
            status: "warn",
            detail: `Master realm hosts ${apps.length} application client(s): ${apps
              .slice(0, 8)
              .map((c) => c.clientId)
              .join(", ")}${apps.length > 8 ? "…" : ""}. Use a dedicated realm for applications.`,
          }),
        );
      }
    }

    return out;
  },
};
