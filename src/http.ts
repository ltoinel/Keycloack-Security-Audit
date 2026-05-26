import { Agent, type Dispatcher } from "undici";

/**
 * Provides an undici dispatcher that disables TLS verification when requested.
 * Use only for internal labs (KC_TLS_VERIFY=false).
 */
export function dispatcherFor(tlsVerify: boolean): Dispatcher | undefined {
  if (tlsVerify) return undefined;
  return new Agent({ connect: { rejectUnauthorized: false } });
}

export interface FetchResult {
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
  url: string;
}

/** Network-error-tolerant fetch: does not throw, returns the status. */
export async function safeFetch(
  url: string,
  init: RequestInit & { dispatcher?: Dispatcher } = {},
): Promise<FetchResult | { error: string }> {
  try {
    const res = await fetch(url, init as RequestInit);
    const body = await res.text();
    return {
      status: res.status,
      ok: res.ok,
      headers: res.headers,
      body,
      url: res.url,
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}
