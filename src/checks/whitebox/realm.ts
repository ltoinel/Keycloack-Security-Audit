import type { Check, Finding } from "../types.js";
import { finding, parsePasswordPolicy } from "./helpers.js";

interface RealmRep {
  realm: string;
  sslRequired?: string;
  bruteForceProtected?: boolean;
  failureFactor?: number;
  passwordPolicy?: string;
  accessTokenLifespan?: number;
  ssoSessionIdleTimeout?: number;
  ssoSessionMaxLifespan?: number;
  revokeRefreshToken?: boolean;
  registrationAllowed?: boolean;
  resetPasswordAllowed?: boolean;
  verifyEmail?: boolean;
  loginWithEmailAllowed?: boolean;
  duplicateEmailsAllowed?: boolean;
  editUsernameAllowed?: boolean;
  browserSecurityHeaders?: Record<string, string>;
}

export const realmCheck: Check = {
  name: "realm",
  mode: "white",
  async run(ctx): Promise<Finding[]> {
    const realm = await ctx.admin!.get<RealmRep>(`/${ctx.realm}`);
    const out: Finding[] = [];

    // --- SSL required -----------------------------------------------------
    out.push(
      finding("realm.ssl-required", {
        resource: realm.realm,
        severity: "high",
        status: realm.sslRequired === "all" ? "pass" : "fail",
        detail: `sslRequired = "${realm.sslRequired ?? "none"}".`,
      }),
    );

    // --- Brute force ------------------------------------------------------
    out.push(
      finding("realm.brute-force", {
        resource: realm.realm,
        severity: "high",
        status: realm.bruteForceProtected ? "pass" : "fail",
        detail: realm.bruteForceProtected
          ? `Enabled (failureFactor=${realm.failureFactor ?? "?"}).`
          : "Brute-force detection is disabled.",
      }),
    );

    // --- Password policy --------------------------------------------------
    const policy = parsePasswordPolicy(realm.passwordPolicy);
    const minLen = Number(policy.get("length") ?? 0);
    out.push(
      finding("realm.password-policy", {
        resource: realm.realm,
        severity: minLen >= 12 ? "low" : "high",
        status: realm.passwordPolicy ? (minLen >= 12 ? "pass" : "warn") : "fail",
        detail: realm.passwordPolicy
          ? `Policy: "${realm.passwordPolicy}" (min length = ${minLen || "undefined"}).`
          : "No password policy defined.",
      }),
    );

    // --- Access token lifespan --------------------------------------------
    const atl = realm.accessTokenLifespan ?? 0;
    out.push(
      finding("realm.access-token-lifespan", {
        resource: realm.realm,
        severity: "medium",
        status: atl === 0 ? "warn" : atl <= 300 ? "pass" : "warn",
        detail: `accessTokenLifespan = ${atl}s.`,
      }),
    );

    // --- Refresh token revocation -----------------------------------------
    out.push(
      finding("realm.refresh-token-rotation", {
        resource: realm.realm,
        severity: "medium",
        status: realm.revokeRefreshToken ? "pass" : "warn",
        detail: `revokeRefreshToken = ${Boolean(realm.revokeRefreshToken)}.`,
      }),
    );

    // --- User enumeration via duplicate emails ----------------------------
    if (realm.duplicateEmailsAllowed) {
      out.push(
        finding("realm.duplicate-emails", {
          resource: realm.realm,
          severity: "low",
          status: "warn",
          detail: "duplicateEmailsAllowed = true.",
        }),
      );
    }

    // --- Email verification -----------------------------------------------
    out.push(
      finding("realm.verify-email", {
        resource: realm.realm,
        severity: "low",
        status: realm.verifyEmail ? "pass" : "warn",
        detail: `verifyEmail = ${Boolean(realm.verifyEmail)}.`,
      }),
    );

    // --- Public self-registration -----------------------------------------
    if (realm.registrationAllowed) {
      out.push(
        finding("realm.self-registration", {
          resource: realm.realm,
          severity: "medium",
          status: "warn",
          detail: "registrationAllowed = true: anyone can create an account.",
        }),
      );
    }

    // --- Browser security headers -----------------------------------------
    const bsh = realm.browserSecurityHeaders ?? {};
    const csp = bsh.contentSecurityPolicy ?? "";
    out.push(
      finding("realm.csp", {
        resource: realm.realm,
        severity: "medium",
        status:
          csp.includes("frame-src") || csp.includes("frame-ancestors")
            ? "pass"
            : "warn",
        detail: `contentSecurityPolicy = "${csp || "(empty)"}".`,
      }),
    );

    return out;
  },
};
