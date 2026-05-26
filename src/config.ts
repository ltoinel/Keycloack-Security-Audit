import "dotenv/config";
import type { AuditConfig } from "./types.js";

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * Builds the configuration from environment variables, overridden by CLI
 * options.
 */
export function loadConfig(overrides: Partial<AuditConfig> = {}): AuditConfig {
  const baseUrl = overrides.baseUrl ?? process.env.KC_BASE_URL;
  if (!baseUrl) {
    throw new Error(
      "Missing Keycloak URL. Provide it as an argument (keycloak-security-audit <url>), via --url, or via KC_BASE_URL in .env.",
    );
  }

  return {
    baseUrl: stripTrailingSlash(baseUrl),
    realm: overrides.realm ?? process.env.KC_REALM ?? "master",
    version: (overrides.version ?? process.env.KC_VERSION)?.trim() || undefined,
    tlsVerify:
      overrides.tlsVerify ??
      (process.env.KC_TLS_VERIFY ?? "true").toLowerCase() !== "false",
    adminUser: overrides.adminUser ?? process.env.KC_ADMIN_USER,
    adminPassword: overrides.adminPassword ?? process.env.KC_ADMIN_PASSWORD,
    adminClientId:
      overrides.adminClientId ?? process.env.KC_ADMIN_CLIENT_ID ?? "admin-cli",
    adminClientSecret:
      overrides.adminClientSecret ?? process.env.KC_ADMIN_CLIENT_SECRET,
  };
}

export function hasAdminCredentials(cfg: AuditConfig): boolean {
  const passwordGrant = Boolean(cfg.adminUser && cfg.adminPassword);
  const clientGrant = Boolean(cfg.adminClientId && cfg.adminClientSecret);
  return passwordGrant || clientGrant;
}
