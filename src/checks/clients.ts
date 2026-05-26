import type { Check, Finding } from "../types.js";
import { finding, dangerousRedirectUris } from "./helpers.js";

const CAT = "Clients";
const DOC =
  "https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients";

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
  redirectUris?: string[];
  webOrigins?: string[];
  attributes?: Record<string, string>;
}

export const clientsCheck: Check = {
  name: "clients",
  mode: "white",
  async run(ctx): Promise<Finding[]> {
    const clients = await ctx.admin!.get<ClientRep[]>(
      `/${ctx.realm}/clients`,
    );
    const out: Finding[] = [];

    for (const c of clients) {
      const isOidc = (c.protocol ?? "openid-connect") === "openid-connect";
      if (!isOidc || c.bearerOnly) continue;

      // --- Implicit flow (deprecated) ------------------------------------
      if (c.implicitFlowEnabled) {
        out.push(
          finding({
            id: "client.implicit-flow",
            title: "Implicit Flow enabled",
            category: CAT,
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Client "${c.clientId}" allows the Implicit Flow (token exposed in the URL).`,
            recommendation:
              "Disable the Implicit Flow and use the Standard Flow + PKCE.",
            references: [DOC],
          }),
        );
      }

      // --- Direct Access Grants (ROPC) -----------------------------------
      if (c.directAccessGrantsEnabled) {
        out.push(
          finding({
            id: "client.direct-access-grants",
            title: "Direct Access Grants (ROPC) enabled",
            category: CAT,
            resource: c.clientId,
            severity: "medium",
            status: "warn",
            detail: `Client "${c.clientId}" allows the password grant (ROPC).`,
            recommendation:
              "Disable ROPC unless a legacy use case justifies it; prefer the authorization code flow.",
            references: [DOC],
          }),
        );
      }

      // --- PKCE on public client -----------------------------------------
      if (c.publicClient && c.standardFlowEnabled) {
        const pkce = c.attributes?.["pkce.code.challenge.method"];
        out.push(
          finding({
            id: "client.pkce",
            title: "PKCE on public client",
            category: CAT,
            resource: c.clientId,
            severity: pkce === "S256" ? "low" : "high",
            status: pkce === "S256" ? "pass" : "fail",
            detail:
              pkce === "S256"
                ? `PKCE S256 enforced on "${c.clientId}".`
                : `Public client "${c.clientId}" does not enforce PKCE (method = ${pkce ?? "none"}).`,
            recommendation:
              'Enforce PKCE with the S256 method (attribute pkce.code.challenge.method = "S256").',
            references: [DOC],
          }),
        );
      }

      // --- Service account on public client ------------------------------
      if (c.publicClient && c.serviceAccountsEnabled) {
        out.push(
          finding({
            id: "client.public-service-account",
            title: "Service account on public client",
            category: CAT,
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Client "${c.clientId}" is public AND has a service account (inconsistent / risky).`,
            recommendation:
              "A service account requires a confidential client with authentication.",
            references: [DOC],
          }),
        );
      }

      // --- Overly broad redirect URIs ------------------------------------
      const bad = dangerousRedirectUris(c.redirectUris);
      if (bad.length > 0) {
        out.push(
          finding({
            id: "client.redirect-uris",
            title: "Overly permissive redirect URI",
            category: CAT,
            resource: c.clientId,
            severity: "high",
            status: "fail",
            detail: `Risky redirect URIs on "${c.clientId}": ${bad.join(", ")}.`,
            recommendation:
              "List exact HTTPS URIs, without domain wildcards or non-local http.",
            references: [DOC],
          }),
        );
      }

      // --- Web Origins (CORS) wildcard -----------------------------------
      if (c.webOrigins?.includes("*")) {
        out.push(
          finding({
            id: "client.web-origins",
            title: "Web Origins CORS = *",
            category: CAT,
            resource: c.clientId,
            severity: "medium",
            status: "fail",
            detail: `Client "${c.clientId}" allows all CORS origins (*).`,
            recommendation: "Restrict Web Origins to the application's domains.",
            references: [DOC],
          }),
        );
      }
    }

    if (out.length === 0) {
      out.push(
        finding({
          id: "client.ok",
          title: "Client configuration",
          category: CAT,
          severity: "info",
          status: "pass",
          detail: `${clients.length} client(s) analyzed, no major configuration issue detected.`,
        }),
      );
    }

    return out;
  },
};
