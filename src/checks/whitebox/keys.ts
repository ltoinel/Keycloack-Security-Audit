import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";

interface KeyRep {
  algorithm?: string;
  status?: string;
  use?: string;
  type?: string;
  kid?: string;
}
interface KeysResponse {
  active?: Record<string, string>;
  keys?: KeyRep[];
}

// Signature algorithms considered robust for tokens.
const STRONG_SIG = new Set(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"]);

export const keysCheck: Check = {
  name: "keys",
  mode: "white",
  async run(ctx): Promise<Finding[]> {
    const data = await ctx.admin!.get<KeysResponse>(`/${ctx.realm}/keys`);
    const out: Finding[] = [];
    const sigKeys = (data.keys ?? []).filter(
      (k) => (k.use ?? "SIG") === "SIG" && k.status === "ACTIVE",
    );

    // --- Active signature algorithm --------------------------------------
    const weak = sigKeys.filter(
      (k) => k.algorithm && !STRONG_SIG.has(k.algorithm),
    );
    out.push(
      finding("keys.signature-algorithm", {
        resource: ctx.realm,
        severity: weak.length ? "high" : "low",
        status: weak.length ? "warn" : "pass",
        detail: weak.length
          ? `Signature keys with a weak/symmetric algorithm: ${weak
              .map((k) => k.algorithm)
              .join(", ")}.`
          : `Active signature keys: ${
              sigKeys.map((k) => k.algorithm).join(", ") || "(none)"
            }.`,
      }),
    );

    // --- At least one active key ------------------------------------------
    out.push(
      finding("keys.active-present", {
        resource: ctx.realm,
        severity: "high",
        status: sigKeys.length > 0 ? "pass" : "fail",
        detail: `${sigKeys.length} active signature key(s).`,
      }),
    );

    return out;
  },
};
