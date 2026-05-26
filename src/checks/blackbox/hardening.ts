import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

export const hardeningCheck: Check = {
  name: "hardening",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const dispatcher = dispatcherFor(ctx.tlsVerify);
    const out: Finding[] = [];
    const u = new URL(ctx.baseUrl);

    // --- Information disclosure via response headers ---------------------
    const infoRes = await safeFetch(`${ctx.baseUrl}/realms/${ctx.realm}`, {
      redirect: "manual",
      dispatcher,
    });
    if (!("error" in infoRes)) {
      const server = infoRes.headers.get("server");
      const xpb = infoRes.headers.get("x-powered-by");
      const leaks: string[] = [];
      // A bare product name is minor; a version string is the real disclosure.
      if (server && (/\d+\.\d+/.test(server) || /keycloak|wildfly|quarkus|undertow|jetty|tomcat/i.test(server)))
        leaks.push(`Server: ${server}`);
      if (xpb) leaks.push(`X-Powered-By: ${xpb}`);
      out.push(
        finding("hardening.server-header", {
          resource: ctx.baseUrl,
          severity: "low",
          status: leaks.length ? "warn" : "pass",
          detail: leaks.length
            ? `Response advertises server technology: ${leaks.join("; ")}.`
            : "No revealing Server / X-Powered-By header.",
        }),
      );
    }

    // --- HTTP -> HTTPS redirect ------------------------------------------
    if (u.protocol !== "https:") {
      out.push(
        finding("hardening.http-redirect", {
          resource: ctx.baseUrl,
          severity: "info",
          status: "skipped",
          detail: "Target is audited over HTTP; see the TLS/HTTPS check.",
        }),
      );
    } else {
      const httpRes = await safeFetch(`http://${u.hostname}/`, {
        redirect: "manual",
        dispatcher,
      });
      if ("error" in httpRes) {
        out.push(
          finding("hardening.http-redirect", {
            resource: `http://${u.hostname}/`,
            severity: "low",
            status: "pass",
            detail: "No plaintext HTTP listener reachable (or it refused the connection).",
          }),
        );
      } else {
        const loc = httpRes.headers.get("location") ?? "";
        const redirectsToHttps =
          httpRes.status >= 300 && httpRes.status < 400 && /^https:/i.test(loc);
        out.push(
          finding("hardening.http-redirect", {
            resource: `http://${u.hostname}/`,
            severity: "medium",
            status: redirectsToHttps ? "pass" : "warn",
            detail: redirectsToHttps
              ? `Plaintext HTTP redirects to HTTPS (${httpRes.status} -> ${loc}).`
              : `Plaintext HTTP responds with HTTP ${httpRes.status} without redirecting to HTTPS.`,
          }),
        );
      }
    }

    // --- Clickjacking protection on the login page -----------------------
    const redirectUri = `${ctx.baseUrl}/realms/${ctx.realm}/account/`;
    const loginUrl =
      `${ctx.baseUrl}/realms/${ctx.realm}/protocol/openid-connect/auth` +
      `?client_id=account&response_type=code&scope=openid&redirect_uri=${encodeURIComponent(redirectUri)}`;
    const loginRes = await safeFetch(loginUrl, { dispatcher });
    if (!("error" in loginRes)) {
      const xfo = loginRes.headers.get("x-frame-options") ?? "";
      const csp = loginRes.headers.get("content-security-policy") ?? "";
      const framingBlocked =
        /sameorigin|deny/i.test(xfo) || /frame-ancestors/i.test(csp);
      out.push(
        finding("hardening.login-clickjacking", {
          resource: loginUrl,
          severity: "medium",
          status: framingBlocked ? "pass" : "warn",
          detail: framingBlocked
            ? `Login page restricts framing (X-Frame-Options="${xfo || "(none)"}", CSP frame-ancestors ${/frame-ancestors/i.test(csp) ? "set" : "absent"}).`
            : "Login page sets neither X-Frame-Options nor CSP frame-ancestors (clickjacking risk).",
        }),
      );
    }

    return out;
  },
};
