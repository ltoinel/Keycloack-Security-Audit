import type { Check, Finding } from "../../types.js";
import { finding, parsePasswordPolicy } from "../helpers.js";

interface RealmRep {
  realm: string;
  sslRequired?: string;
  bruteForceProtected?: boolean;
  failureFactor?: number;
  permanentLockout?: boolean;
  maxFailureWaitSeconds?: number;
  passwordPolicy?: string;
  accessTokenLifespan?: number;
  ssoSessionIdleTimeout?: number;
  ssoSessionMaxLifespan?: number;
  offlineSessionIdleTimeout?: number;
  offlineSessionMaxLifespanEnabled?: boolean;
  offlineSessionMaxLifespan?: number;
  revokeRefreshToken?: boolean;
  registrationAllowed?: boolean;
  resetPasswordAllowed?: boolean;
  verifyEmail?: boolean;
  loginWithEmailAllowed?: boolean;
  duplicateEmailsAllowed?: boolean;
  editUsernameAllowed?: boolean;
  eventsEnabled?: boolean;
  eventsListeners?: string[];
  adminEventsEnabled?: boolean;
  adminEventsDetailsEnabled?: boolean;
  otpPolicyType?: string;
  otpPolicyAlgorithm?: string;
  otpPolicyDigits?: number;
  otpPolicyPeriod?: number;
  webAuthnPolicyUserVerificationRequirement?: string;
  webAuthnPolicyAttestationConveyancePreference?: string;
  webAuthnPolicySignatureAlgorithms?: string[];
  webAuthnPolicyPasswordlessUserVerificationRequirement?: string;
  webAuthnPolicyPasswordlessAttestationConveyancePreference?: string;
  smtpServer?: Record<string, string>;
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

    // --- Brute-force tuning (only when protection is on) ------------------
    if (realm.bruteForceProtected) {
      const ff = realm.failureFactor ?? 0;
      out.push(
        finding("realm.brute-force-tuning", {
          resource: realm.realm,
          severity: "medium",
          status: ff >= 1 && ff <= 10 ? "pass" : "warn",
          detail: `failureFactor=${ff}, permanentLockout=${Boolean(
            realm.permanentLockout,
          )}, maxFailureWaitSeconds=${realm.maxFailureWaitSeconds ?? "?"}s.`,
        }),
      );
    }

    // --- Password hashing strength ---------------------------------------
    const hashAlg = policy.get("hashAlgorithm");
    const hashIter = Number(policy.get("hashIterations") ?? 0);
    const strongHash =
      hashAlg === "argon2" ||
      (hashAlg === "pbkdf2-sha512" && hashIter >= 210000) ||
      (hashAlg === "pbkdf2-sha256" && hashIter >= 600000);
    out.push(
      finding("realm.password-hashing", {
        resource: realm.realm,
        severity: strongHash ? "low" : "medium",
        status: strongHash ? "pass" : "warn",
        detail: hashAlg
          ? `hashAlgorithm=${hashAlg}, hashIterations=${hashIter || "(default)"}.`
          : "No explicit hashAlgorithm/hashIterations set; relying on the server default.",
      }),
    );

    // --- SSO session idle timeout ----------------------------------------
    const ssoIdle = realm.ssoSessionIdleTimeout ?? 0;
    out.push(
      finding("realm.sso-session-idle", {
        resource: realm.realm,
        severity: "medium",
        status: ssoIdle > 0 && ssoIdle <= 1800 ? "pass" : "warn",
        detail: `ssoSessionIdleTimeout = ${ssoIdle}s.`,
      }),
    );

    // --- SSO session max lifespan ----------------------------------------
    const ssoMax = realm.ssoSessionMaxLifespan ?? 0;
    out.push(
      finding("realm.sso-session-max", {
        resource: realm.realm,
        severity: "medium",
        status: ssoMax > 0 && ssoMax <= 36000 ? "pass" : "warn",
        detail: `ssoSessionMaxLifespan = ${ssoMax}s.`,
      }),
    );

    // --- Offline session lifespan ----------------------------------------
    const offlineCapped = realm.offlineSessionMaxLifespanEnabled === true;
    out.push(
      finding("realm.offline-session", {
        resource: realm.realm,
        severity: "low",
        status: offlineCapped ? "pass" : "warn",
        detail: offlineCapped
          ? `Offline session capped (offlineSessionMaxLifespan=${realm.offlineSessionMaxLifespan ?? "?"}s, idle=${realm.offlineSessionIdleTimeout ?? "?"}s).`
          : `offlineSessionMaxLifespanEnabled = false: offline tokens expire only on idle (${realm.offlineSessionIdleTimeout ?? "?"}s), not by absolute lifetime.`,
      }),
    );

    // --- Login event logging ---------------------------------------------
    out.push(
      finding("realm.login-events", {
        resource: realm.realm,
        severity: "medium",
        status: realm.eventsEnabled ? "pass" : "warn",
        detail: realm.eventsEnabled
          ? `Login event logging enabled${
              realm.eventsListeners?.length
                ? ` (listeners: ${realm.eventsListeners.join(", ")})`
                : ""
            }.`
          : "eventsEnabled = false: login events are not recorded.",
      }),
    );

    // --- Admin event logging ---------------------------------------------
    out.push(
      finding("realm.admin-events", {
        resource: realm.realm,
        severity: "medium",
        status: realm.adminEventsEnabled ? "pass" : "warn",
        detail: realm.adminEventsEnabled
          ? `Admin event logging enabled${realm.adminEventsDetailsEnabled ? " (with details)" : ""}.`
          : "adminEventsEnabled = false: administrative changes are not audited.",
      }),
    );

    // --- OTP policy -------------------------------------------------------
    const otpDigits = realm.otpPolicyDigits ?? 6;
    out.push(
      finding("realm.otp-policy", {
        resource: realm.realm,
        severity: "low",
        status: otpDigits >= 6 ? "pass" : "warn",
        detail: `OTP: type=${realm.otpPolicyType ?? "totp"}, algorithm=${realm.otpPolicyAlgorithm ?? "?"}, digits=${otpDigits}, period=${realm.otpPolicyPeriod ?? "?"}s.`,
      }),
    );

    // --- WebAuthn policy --------------------------------------------------
    const uv = realm.webAuthnPolicyUserVerificationRequirement;
    out.push(
      finding("realm.webauthn-policy", {
        resource: realm.realm,
        severity: "low",
        status: uv === "discouraged" ? "warn" : "pass",
        detail: `WebAuthn: userVerification=${uv ?? "(default)"}, attestation=${realm.webAuthnPolicyAttestationConveyancePreference ?? "(default)"}.`,
      }),
    );

    // --- WebAuthn passwordless policy ------------------------------------
    const pwlUv = realm.webAuthnPolicyPasswordlessUserVerificationRequirement;
    out.push(
      finding("realm.webauthn-passwordless", {
        resource: realm.realm,
        severity: "low",
        status: !pwlUv || pwlUv === "required" ? "pass" : "warn",
        detail: `Passwordless WebAuthn: userVerification=${pwlUv ?? "(default)"}, attestation=${realm.webAuthnPolicyPasswordlessAttestationConveyancePreference ?? "(default)"}.`,
      }),
    );

    // --- SMTP / email transport ------------------------------------------
    const smtp = realm.smtpServer ?? {};
    const smtpTls = smtp.ssl === "true" || smtp.starttls === "true";
    out.push(
      finding("realm.smtp", {
        resource: realm.realm,
        severity: "low",
        status: smtp.host ? (smtpTls ? "pass" : "warn") : "warn",
        detail: smtp.host
          ? smtpTls
            ? `SMTP over TLS (host=${smtp.host}, ssl=${smtp.ssl ?? "false"}, starttls=${smtp.starttls ?? "false"}).`
            : `SMTP host ${smtp.host} configured without TLS (ssl/starttls disabled).`
          : "No SMTP server configured; email verification and password reset cannot work.",
      }),
    );

    return out;
  },
};
