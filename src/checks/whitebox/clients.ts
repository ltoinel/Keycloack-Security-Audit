import type { Check, Finding } from "../types.js";
import { finding, dangerousRedirectUris } from "./helpers.js";

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

    return out;
  },
};
