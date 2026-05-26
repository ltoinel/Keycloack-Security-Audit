import type { Check, Finding } from "../types.js";
import { finding, parsePasswordPolicy } from "./helpers.js";

const CAT = "Realm";
const DOC = "https://www.keycloak.org/docs/latest/server_admin/";

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
      finding({
        id: "realm.ssl-required",
        title: "SSL/HTTPS required",
        category: CAT,
        resource: realm.realm,
        severity: "high",
        status: realm.sslRequired === "all" ? "pass" : "fail",
        detail: `sslRequired = "${realm.sslRequired ?? "none"}".`,
        recommendation:
          'Set sslRequired to "all" to enforce HTTPS, including on the internal network.',
        references: [DOC],
      }),
    );

    // --- Brute force ------------------------------------------------------
    out.push(
      finding({
        id: "realm.brute-force",
        title: "Brute-force protection",
        category: CAT,
        resource: realm.realm,
        severity: "high",
        status: realm.bruteForceProtected ? "pass" : "fail",
        detail: realm.bruteForceProtected
          ? `Enabled (failureFactor=${realm.failureFactor ?? "?"}).`
          : "Brute-force detection is disabled.",
        recommendation:
          "Enable brute-force protection with a reasonable failureFactor (e.g. 5 to 10).",
        references: [DOC],
      }),
    );

    // --- Password policy --------------------------------------------------
    const policy = parsePasswordPolicy(realm.passwordPolicy);
    const minLen = Number(policy.get("length") ?? 0);
    out.push(
      finding({
        id: "realm.password-policy",
        title: "Password policy",
        category: CAT,
        resource: realm.realm,
        severity: minLen >= 12 ? "low" : "high",
        status: realm.passwordPolicy
          ? minLen >= 12
            ? "pass"
            : "warn"
          : "fail",
        detail: realm.passwordPolicy
          ? `Policy: "${realm.passwordPolicy}" (min length = ${minLen || "undefined"}).`
          : "No password policy defined.",
        recommendation:
          "Define at least length(12), notUsername, and ideally passwordHistory + a blacklist.",
        references: [DOC],
      }),
    );

    // --- Access token lifespan --------------------------------------------
    const atl = realm.accessTokenLifespan ?? 0;
    out.push(
      finding({
        id: "realm.access-token-lifespan",
        title: "Access token lifespan",
        category: CAT,
        resource: realm.realm,
        severity: "medium",
        status: atl === 0 ? "warn" : atl <= 300 ? "pass" : "warn",
        detail: `accessTokenLifespan = ${atl}s.`,
        recommendation:
          "Keep the access token short (<= 300s) and rely on the refresh token.",
        references: [DOC],
      }),
    );

    // --- Refresh token revocation -----------------------------------------
    out.push(
      finding({
        id: "realm.refresh-token-rotation",
        title: "Refresh token revocation / rotation",
        category: CAT,
        resource: realm.realm,
        severity: "medium",
        status: realm.revokeRefreshToken ? "pass" : "warn",
        detail: `revokeRefreshToken = ${Boolean(realm.revokeRefreshToken)}.`,
        recommendation:
          "Enable refresh token revocation (rotation) to limit replay attacks.",
        references: [DOC],
      }),
    );

    // --- User enumeration via duplicate emails / login with email ---------
    if (realm.duplicateEmailsAllowed) {
      out.push(
        finding({
          id: "realm.duplicate-emails",
          title: "Duplicate emails allowed",
          category: CAT,
          resource: realm.realm,
          severity: "low",
          status: "warn",
          detail: "duplicateEmailsAllowed = true.",
          recommendation:
            "Disallow duplicate emails unless there is an explicit business need.",
          references: [DOC],
        }),
      );
    }

    // --- Email verification -----------------------------------------------
    out.push(
      finding({
        id: "realm.verify-email",
        title: "Email verification",
        category: CAT,
        resource: realm.realm,
        severity: "low",
        status: realm.verifyEmail ? "pass" : "warn",
        detail: `verifyEmail = ${Boolean(realm.verifyEmail)}.`,
        recommendation:
          "Enable email verification to strengthen account identity.",
        references: [DOC],
      }),
    );

    // --- Public self-registration -----------------------------------------
    if (realm.registrationAllowed) {
      out.push(
        finding({
          id: "realm.self-registration",
          title: "Self-registration enabled",
          category: CAT,
          resource: realm.realm,
          severity: "medium",
          status: "warn",
          detail: "registrationAllowed = true: anyone can create an account.",
          recommendation:
            "Disable self-registration if the realm is intended for internal users.",
          references: [DOC],
        }),
      );
    }

    // --- Browser security headers -----------------------------------------
    const bsh = realm.browserSecurityHeaders ?? {};
    const csp = bsh.contentSecurityPolicy ?? "";
    out.push(
      finding({
        id: "realm.csp",
        title: "Content-Security-Policy",
        category: CAT,
        resource: realm.realm,
        severity: "medium",
        status: csp.includes("frame-src") || csp.includes("frame-ancestors")
          ? "pass"
          : "warn",
        detail: `contentSecurityPolicy = "${csp || "(empty)"}".`,
        recommendation:
          "Keep a restrictive CSP (frame-ancestors 'self') to limit clickjacking.",
        references: [DOC],
      }),
    );

    return out;
  },
};
