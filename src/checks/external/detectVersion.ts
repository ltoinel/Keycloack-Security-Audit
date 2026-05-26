import type { CheckContext } from "../../types.js";
import { safeFetch, dispatcherFor } from "../../http.js";

/**
 * Passive detection of the Keycloak version.
 * The version appears in the console's static resource paths
 * (/resources/{version}/...). No intrusive request.
 *
 * @returns the detected version, or undefined if not identifiable.
 */
export async function detectKeycloakVersion(
  ctx: CheckContext,
): Promise<string | undefined> {
  const url = `${ctx.baseUrl}/admin/master/console/`;
  const res = await safeFetch(url, { dispatcher: dispatcherFor(ctx.tlsVerify) });
  if ("error" in res) return undefined;

  const match =
    res.body.match(/\/resources\/([^/]+)\/admin/) ??
    res.body.match(/resourceVersion["']?\s*[:=]\s*["']([^"']+)/i);
  return match?.[1];
}

/**
 * Resolves the Keycloak version to audit against: a version provided manually
 * (CLI `--kc-version` / `KC_VERSION`) takes precedence; otherwise fall back to
 * passive detection.
 */
export async function resolveKeycloakVersion(
  ctx: CheckContext,
): Promise<string | undefined> {
  return ctx.version || detectKeycloakVersion(ctx);
}
