import type { Dispatcher } from "undici";
import type { AdminApi, AuditConfig } from "../types.js";
import { dispatcherFor } from "../http.js";

interface TokenResponse {
  access_token: string;
  expires_in: number;
}

/**
 * Authenticates against the configured admin realm's token endpoint
 * (`cfg.adminRealm`, default = the audited realm) and returns an Admin REST API
 * client. Tries the client_credentials grant first (service account), then
 * falls back to the password grant.
 *
 * Throws an explicit error if no authentication succeeds; the caller can then
 * fall back to black-box mode only.
 */
export async function createAdminApi(cfg: AuditConfig): Promise<AdminApi> {
  const dispatcher = dispatcherFor(cfg.tlsVerify);
  const tokenUrl = `${cfg.baseUrl}/realms/${cfg.adminRealm}/protocol/openid-connect/token`;

  const token = await fetchToken(cfg, tokenUrl, dispatcher);

  const get = async <T>(path: string): Promise<T> => {
    const clean = path.replace(/^\/+/, "");
    const url = `${cfg.baseUrl}/admin/realms/${clean}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      dispatcher,
    } as RequestInit);
    if (!res.ok) {
      throw new Error(`Admin API ${res.status} on ${url}`);
    }
    return (await res.json()) as T;
  };

  return { get };
}

async function fetchToken(
  cfg: AuditConfig,
  tokenUrl: string,
  dispatcher: Dispatcher | undefined,
): Promise<string> {
  const params = new URLSearchParams();

  if (cfg.adminClientSecret) {
    params.set("grant_type", "client_credentials");
    params.set("client_id", cfg.adminClientId);
    params.set("client_secret", cfg.adminClientSecret);
  } else if (cfg.adminUser && cfg.adminPassword) {
    params.set("grant_type", "password");
    params.set("client_id", cfg.adminClientId);
    params.set("username", cfg.adminUser);
    params.set("password", cfg.adminPassword);
  } else {
    throw new Error("No admin credentials provided");
  }

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    dispatcher,
  } as RequestInit);

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Admin API authentication failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }

  const json = (await res.json()) as TokenResponse;
  return json.access_token;
}
