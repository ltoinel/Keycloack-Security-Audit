import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { headerRules, type ExpectRule } from "../registry.js";
import { safeFetch, dispatcherFor } from "../../http.js";

/** Evaluates a header value against its declarative expectation from the config. */
export function meetsExpectation(value: string, expect?: ExpectRule): boolean {
  if (!expect) return true; // presence alone is enough
  if (
    expect.equals !== undefined &&
    value.toLowerCase() !== expect.equals.toLowerCase()
  ) {
    return false;
  }
  if (expect.regex !== undefined) {
    let re: RegExp;
    try {
      re = new RegExp(expect.regex, "i");
    } catch {
      return false; // invalid regex in config -> treat as not satisfied
    }
    if (!re.test(value)) return false;
  }
  if (expect.minMaxAge !== undefined) {
    const m = value.match(/max-age=(\d+)/i);
    if (!m || Number(m[1]) < expect.minMaxAge) return false;
  }
  return true;
}

export const headersCheck: Check = {
  name: "headers",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const url = `${ctx.baseUrl}/realms/${ctx.realm}/account`;
    const res = await safeFetch(url, {
      redirect: "manual",
      dispatcher: dispatcherFor(ctx.tlsVerify),
    });

    if ("error" in res) {
      return [
        finding("headers.fetch", {
          severity: "info",
          status: "error",
          detail: `Request failed: ${res.error}.`,
          resource: url,
        }),
      ];
    }

    // Header rules are defined entirely in checks.yaml (id, header, severity, expect).
    return headerRules().map((rule) => {
      const value = res.headers.get(rule.header);
      const present = value !== null;
      const ok = present && meetsExpectation(value, rule.expect);
      return finding(rule.id, {
        resource: ctx.baseUrl,
        severity: rule.severity,
        status: ok ? "pass" : present ? "warn" : "fail",
        detail: present
          ? `Present: "${value}".`
          : "Header missing from the response.",
      });
    });
  },
};
