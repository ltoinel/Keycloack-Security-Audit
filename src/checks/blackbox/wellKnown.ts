import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

interface OidcConfig {
  grant_types_supported?: string[];
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  code_challenge_methods_supported?: string[];
  token_endpoint?: string;
}

export const wellKnownCheck: Check = {
  name: "well-known",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const url = `${ctx.baseUrl}/realms/${ctx.realm}/.well-known/openid-configuration`;
    const res = await safeFetch(url, {
      dispatcher: dispatcherFor(ctx.tlsVerify),
    });

    if ("error" in res || !res.ok) {
      return [
        finding("wellknown.fetch", {
          resource: url,
          severity: "info",
          status: "error",
          detail:
            "error" in res ? `Request failed: ${res.error}.` : `HTTP ${res.status}.`,
        }),
      ];
    }

    let cfg: OidcConfig;
    try {
      cfg = JSON.parse(res.body) as OidcConfig;
    } catch {
      return [
        finding("wellknown.parse", {
          resource: url,
          severity: "info",
          status: "error",
          detail: "Non-JSON response.",
        }),
      ];
    }

    const out: Finding[] = [];

    // --- Advertised signature algorithms ---------------------------------
    const algs = cfg.id_token_signing_alg_values_supported ?? [];
    const hasNone = algs.map((a) => a.toLowerCase()).includes("none");
    out.push(
      finding("wellknown.alg-none", {
        resource: ctx.realm,
        severity: hasNone ? "critical" : "low",
        status: hasNone ? "fail" : "pass",
        detail: hasNone
          ? 'id_token_signing_alg_values_supported includes "none".'
          : `Algorithms: ${algs.join(", ") || "(not advertised)"}.`,
      }),
    );

    // --- PKCE advertised --------------------------------------------------
    const pkce = cfg.code_challenge_methods_supported ?? [];
    out.push(
      finding("wellknown.pkce", {
        resource: ctx.realm,
        severity: "low",
        status: pkce.includes("S256") ? "pass" : "warn",
        detail: `code_challenge_methods_supported = [${pkce.join(", ")}].`,
      }),
    );

    // --- Implicit flow advertised -----------------------------------------
    const responseTypes = cfg.response_types_supported ?? [];
    const implicit = responseTypes.some(
      (r) => r.includes("token") && !r.includes("code"),
    );
    out.push(
      finding("wellknown.implicit", {
        resource: ctx.realm,
        severity: "low",
        status: implicit ? "warn" : "pass",
        detail: `response_types_supported = [${responseTypes.join(", ")}].`,
      }),
    );

    return out;
  },
};
