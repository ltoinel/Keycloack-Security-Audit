import type { Check, Finding } from "../types.js";
import { finding } from "./helpers.js";

/** Predictable administrative usernames to flag. */
const PREDICTABLE_ADMINS = new Set([
  "admin",
  "administrator",
  "root",
  "kcadmin",
  "sysadmin",
  "keycloak",
]);

/** Maximum number of users probed for MFA coverage. */
const OTP_SAMPLE = 50;

/** Credential types considered a second factor. */
const MFA_TYPES = new Set(["otp", "webauthn", "webauthn-passwordless"]);

interface UserRep {
  id: string;
  username?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  federationLink?: string;
}
interface CredentialRep {
  type?: string;
}

export const usersCheck: Check = {
  name: "users",
  mode: "white",
  async run(ctx): Promise<Finding[]> {
    const users = await ctx.admin!.get<UserRep[]>(
      `/${ctx.realm}/users?max=1000&briefRepresentation=true`,
    );
    const out: Finding[] = [];
    const isMaster = ctx.realm === "master";

    // --- Predictable admin accounts --------------------------------------
    const predictable = users.filter((u) =>
      PREDICTABLE_ADMINS.has((u.username ?? "").toLowerCase()),
    );
    out.push(
      finding("users.predictable-admin", {
        resource: ctx.realm,
        severity: predictable.length ? "medium" : "low",
        status: predictable.length ? "warn" : "pass",
        detail: predictable.length
          ? `Account(s) with a predictable name: ${predictable
              .map((u) => u.username)
              .join(", ")}. Easy target for brute-force / password spraying.`
          : "No trivial administrative account name detected.",
      }),
    );

    // --- MFA / OTP coverage (sampled) ------------------------------------
    const sample = users
      .filter((u) => u.enabled !== false && !u.federationLink)
      .slice(0, OTP_SAMPLE);
    let probed = 0;
    const withoutMfa: string[] = [];
    let credentialsReadable = true;

    for (const u of sample) {
      try {
        const creds = await ctx.admin!.get<CredentialRep[]>(
          `/${ctx.realm}/users/${u.id}/credentials`,
        );
        probed++;
        const hasMfa = creds.some((c) =>
          MFA_TYPES.has((c.type ?? "").toLowerCase()),
        );
        if (!hasMfa) withoutMfa.push(u.username ?? u.id);
      } catch {
        credentialsReadable = false;
        break;
      }
    }

    if (!credentialsReadable || probed === 0) {
      out.push(
        finding("users.mfa-coverage", {
          resource: ctx.realm,
          severity: "info",
          status: "skipped",
          detail:
            "Unable to read credentials (does the service account have the view-users role?).",
          recommendation:
            "Grant the view-users role to the audit account to assess MFA coverage.",
        }),
      );
    } else {
      const ratio = withoutMfa.length / probed;
      // In master, every account is an admin -> strong MFA requirement.
      const severity = isMaster
        ? withoutMfa.length
          ? "high"
          : "low"
        : ratio > 0.5
          ? "medium"
          : "low";
      const preview = withoutMfa.slice(0, 8).join(", ");
      out.push(
        finding("users.mfa-coverage", {
          resource: ctx.realm,
          severity,
          status: withoutMfa.length ? "warn" : "pass",
          detail: withoutMfa.length
            ? `${withoutMfa.length}/${probed} probed account(s) without 2FA (no OTP nor WebAuthn)${
                isMaster ? " (master realm = admin accounts)" : ""
              }: ${preview}${withoutMfa.length > 8 ? "…" : ""}.`
            : `All ${probed} probed account(s) have a second factor (OTP or WebAuthn) configured.`,
          ...(isMaster
            ? {
                recommendation:
                  "Require OTP/MFA for all administrators of the master realm (required action or auth flow).",
              }
            : {}),
        }),
      );
    }

    // --- Disabled accounts (informational) -------------------------------
    const disabled = users.filter((u) => u.enabled === false).length;
    if (disabled > 0) {
      out.push(
        finding("users.disabled", {
          resource: ctx.realm,
          severity: "info",
          status: "pass",
          detail: `${disabled} disabled account(s) — consider purging obsolete accounts.`,
        }),
      );
    }

    return out;
  },
};
