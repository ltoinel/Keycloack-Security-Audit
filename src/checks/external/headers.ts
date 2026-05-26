import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { safeFetch, dispatcherFor } from "../../http.js";

const CAT = "HTTP Headers";

interface HeaderRule {
  header: string;
  id: string;
  title: string;
  severity: "high" | "medium" | "low";
  expected?: (value: string) => boolean;
  recommendation: string;
}

const RULES: HeaderRule[] = [
  {
    header: "strict-transport-security",
    id: "headers.hsts",
    title: "Strict-Transport-Security (HSTS)",
    severity: "medium",
    expected: (v) => /max-age=\d+/.test(v) && Number(v.match(/max-age=(\d+)/)?.[1] ?? 0) >= 31536000,
    recommendation: "Add HSTS with max-age >= 31536000 (1 year).",
  },
  {
    header: "x-content-type-options",
    id: "headers.x-content-type",
    title: "X-Content-Type-Options",
    severity: "low",
    expected: (v) => v.toLowerCase() === "nosniff",
    recommendation: "Set X-Content-Type-Options: nosniff.",
  },
  {
    header: "x-frame-options",
    id: "headers.x-frame-options",
    title: "X-Frame-Options",
    severity: "medium",
    expected: (v) => /sameorigin|deny/i.test(v),
    recommendation: "Set X-Frame-Options: SAMEORIGIN (anti-clickjacking).",
  },
  {
    header: "content-security-policy",
    id: "headers.csp",
    title: "Content-Security-Policy",
    severity: "medium",
    recommendation: "Serve a restrictive CSP including frame-ancestors.",
  },
  {
    header: "referrer-policy",
    id: "headers.referrer-policy",
    title: "Referrer-Policy",
    severity: "low",
    recommendation: "Set a Referrer-Policy (e.g. no-referrer or strict-origin).",
  },
];

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
        finding({
          id: "headers.fetch",
          title: "Header retrieval",
          category: CAT,
          severity: "info",
          status: "error",
          detail: `Request failed: ${res.error}.`,
          resource: url,
        }),
      ];
    }

    return RULES.map((rule) => {
      const value = res.headers.get(rule.header);
      const present = value !== null;
      const ok = present && (rule.expected ? rule.expected(value) : true);
      return finding({
        id: rule.id,
        title: rule.title,
        category: CAT,
        resource: ctx.baseUrl,
        severity: rule.severity,
        status: ok ? "pass" : present ? "warn" : "fail",
        detail: present
          ? `Present: "${value}".`
          : "Header missing from the response.",
        recommendation: rule.recommendation,
      });
    });
  },
};
