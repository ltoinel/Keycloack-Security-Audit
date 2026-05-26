import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

interface Jwk {
  kty?: string;
  alg?: string;
  use?: string;
  n?: string;
  crv?: string;
  kid?: string;
}

/** Bit length of an RSA modulus given its base64url-encoded value (JWK `n`). */
export function rsaBits(n: string): number {
  const buf = Buffer.from(n, "base64url");
  let bits = buf.length * 8;
  if (buf.length > 0 && buf[0] === 0) bits -= 8; // strip a leading zero byte
  return bits;
}

function describe(k: Jwk): string {
  if (k.kty === "RSA" && k.n) return `RSA-${rsaBits(k.n)}`;
  if (k.crv) return `${k.kty}-${k.crv}`;
  return k.kty ?? "unknown";
}

export const jwksCheck: Check = {
  name: "jwks",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const url = `${ctx.baseUrl}/realms/${ctx.realm}/protocol/openid-connect/certs`;
    const res = await safeFetch(url, { dispatcher: dispatcherFor(ctx.tlsVerify) });

    if ("error" in res || !res.ok) {
      return [
        finding("jwks.fetch", {
          resource: url,
          severity: "info",
          status: "error",
          detail:
            "error" in res ? `Request failed: ${res.error}.` : `HTTP ${res.status}.`,
        }),
      ];
    }

    let keys: Jwk[];
    try {
      keys = (JSON.parse(res.body).keys ?? []) as Jwk[];
    } catch {
      return [
        finding("jwks.fetch", {
          resource: url,
          severity: "info",
          status: "error",
          detail: "Non-JSON JWKS response.",
        }),
      ];
    }

    const weak = keys.filter((k) => k.kty === "RSA" && k.n && rsaBits(k.n) < 2048);
    const summary = keys.map(describe).join(", ") || "(none)";

    return [
      finding("jwks.key-strength", {
        resource: ctx.realm,
        severity: weak.length ? "high" : "low",
        status: keys.length === 0 ? "warn" : weak.length ? "fail" : "pass",
        detail:
          keys.length === 0
            ? "JWKS endpoint exposes no keys."
            : `Published keys: ${summary}.${
                weak.length ? " Weak RSA key(s) < 2048 bits detected." : ""
              }`,
      }),
    ];
  },
};
