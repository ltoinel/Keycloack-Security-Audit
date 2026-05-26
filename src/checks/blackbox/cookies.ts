import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

/** Parses a single Set-Cookie header value into its name and security flags. */
export function parseSetCookie(raw: string): ParsedCookie {
  const parts = raw.split(";").map((s) => s.trim());
  const name = parts[0]?.split("=")[0] ?? "";
  const attrs = parts.slice(1);
  const lower = attrs.map((a) => a.toLowerCase());
  const sameSite = attrs.find((a) => /^samesite=/i.test(a));
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
    sameSite: sameSite ? sameSite.split("=")[1] : undefined,
  };
}

export const cookiesCheck: Check = {
  name: "cookies",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    // The OIDC authorization endpoint sets Keycloak's session cookies
    // (AUTH_SESSION_ID, KC_RESTART) on the login page. Built-in `account`
    // client is present in every realm.
    const redirectUri = `${ctx.baseUrl}/realms/${ctx.realm}/account/`;
    const url =
      `${ctx.baseUrl}/realms/${ctx.realm}/protocol/openid-connect/auth` +
      `?client_id=account&response_type=code&scope=openid&redirect_uri=${encodeURIComponent(redirectUri)}`;

    const res = await safeFetch(url, { dispatcher: dispatcherFor(ctx.tlsVerify) });
    if ("error" in res) {
      return [
        finding("cookies.fetch", {
          resource: url,
          severity: "info",
          status: "error",
          detail: `Request failed: ${res.error}.`,
        }),
      ];
    }

    const rawCookies =
      typeof res.headers.getSetCookie === "function"
        ? res.headers.getSetCookie()
        : [];
    const cookies = rawCookies
      .map(parseSetCookie)
      .filter((c) => c.name.length > 0);

    if (cookies.length === 0) {
      return [
        finding("cookies.fetch", {
          resource: url,
          severity: "info",
          status: "skipped",
          detail:
            "No Set-Cookie observed on the login endpoint; cookie flags could not be evaluated.",
        }),
      ];
    }

    const names = cookies.map((c) => c.name).join(", ");
    const noSecure = cookies.filter((c) => !c.secure).map((c) => c.name);
    const noHttpOnly = cookies.filter((c) => !c.httpOnly).map((c) => c.name);
    const noSameSite = cookies.filter((c) => !c.sameSite).map((c) => c.name);

    return [
      finding("cookies.secure", {
        resource: ctx.baseUrl,
        severity: "high",
        status: noSecure.length ? "fail" : "pass",
        detail: noSecure.length
          ? `Cookie(s) without the Secure attribute: ${noSecure.join(", ")}.`
          : `All session cookies set Secure (${names}).`,
      }),
      finding("cookies.http-only", {
        resource: ctx.baseUrl,
        severity: "medium",
        status: noHttpOnly.length ? "warn" : "pass",
        detail: noHttpOnly.length
          ? `Cookie(s) without HttpOnly: ${noHttpOnly.join(", ")}.`
          : `All session cookies set HttpOnly (${names}).`,
      }),
      finding("cookies.same-site", {
        resource: ctx.baseUrl,
        severity: "low",
        status: noSameSite.length ? "warn" : "pass",
        detail: noSameSite.length
          ? `Cookie(s) without a SameSite attribute: ${noSameSite.join(", ")}.`
          : `All session cookies set SameSite (${names}).`,
      }),
    ];
  },
};
