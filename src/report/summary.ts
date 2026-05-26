import type { Finding, Severity, FindingStatus } from "../types.js";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

export const RISK_ORDER: RiskLevel[] = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
];

/** Impact weight per severity — the potential damage if the issue is real. */
export const IMPACT_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 1,
  info: 0,
};

/**
 * Likelihood factor per status — how certain the risk is. A "fail" is a
 * confirmed issue, a "warn" is a potential one (needs review); other statuses
 * carry no residual risk.
 */
export const LIKELIHOOD: Record<FindingStatus, number> = {
  fail: 1,
  warn: 0.5,
  pass: 0,
  skipped: 0,
  error: 0,
};

export interface Risk {
  /** Weighted risk = impact × likelihood (0 to 25). */
  score: number;
  level: RiskLevel;
  /** Severity weight (impact). */
  impact: number;
  /** Status factor (likelihood). */
  likelihood: number;
}

/** Maps a numeric risk score to a qualitative risk level. */
export function riskLevel(score: number): RiskLevel {
  if (score >= 18) return "critical";
  if (score >= 9) return "high";
  if (score >= 3) return "medium";
  if (score > 0) return "low";
  return "none";
}

/** Computes the weighted risk of a finding from its impact and likelihood. */
export function riskOf(f: Finding): Risk {
  const impact = IMPACT_WEIGHT[f.severity];
  const likelihood = LIKELIHOOD[f.status];
  const score = Math.round(impact * likelihood * 10) / 10;
  return { score, level: riskLevel(score), impact, likelihood };
}

export interface Summary {
  total: number;
  byStatus: Record<FindingStatus, number>;
  /** Number of problematic findings (fail + warn) per severity. */
  bySeverity: Record<Severity, number>;
  /** Number of hard failures (fail only) per severity. */
  failuresBySeverity: Record<Severity, number>;
  /** Number of findings per risk level. */
  byRisk: Record<RiskLevel, number>;
  /** Total weighted risk exposure (sum of per-finding risk scores). */
  risk: number;
  /** Score out of 100 (100 = no issues), i.e. 100 − risk exposure. */
  score: number;
}

const STATUS_KEYS: FindingStatus[] = ["fail", "warn", "pass", "skipped", "error"];

export function summarize(findings: Finding[]): Summary {
  const byStatus = Object.fromEntries(
    STATUS_KEYS.map((k) => [k, 0]),
  ) as Record<FindingStatus, number>;
  const bySeverity = Object.fromEntries(
    SEVERITY_ORDER.map((k) => [k, 0]),
  ) as Record<Severity, number>;
  const failuresBySeverity = Object.fromEntries(
    SEVERITY_ORDER.map((k) => [k, 0]),
  ) as Record<Severity, number>;
  const byRisk = Object.fromEntries(
    RISK_ORDER.map((k) => [k, 0]),
  ) as Record<RiskLevel, number>;

  let penalty = 0;
  for (const f of findings) {
    byStatus[f.status]++;
    // Risk = impact (severity) × likelihood (status).
    byRisk[riskOf(f).level]++;
    penalty += IMPACT_WEIGHT[f.severity] * LIKELIHOOD[f.status];
    if (f.status === "fail" || f.status === "warn") {
      bySeverity[f.severity]++;
      if (f.status === "fail") failuresBySeverity[f.severity]++;
    }
  }

  const score = Math.max(0, Math.round(100 - penalty));
  const risk = Math.round(penalty * 10) / 10;
  return {
    total: findings.length,
    byStatus,
    bySeverity,
    failuresBySeverity,
    byRisk,
    risk,
    score,
  };
}

/** Sort: by weighted risk (desc), then status (fail > warn > ...), then severity. */
export function sortFindings(findings: Finding[]): Finding[] {
  const statusRank: Record<FindingStatus, number> = {
    fail: 0,
    warn: 1,
    error: 2,
    pass: 3,
    skipped: 4,
  };
  return [...findings].sort((a, b) => {
    const ra = riskOf(a).score;
    const rb = riskOf(b).score;
    if (ra !== rb) return rb - ra;
    if (statusRank[a.status] !== statusRank[b.status])
      return statusRank[a.status] - statusRank[b.status];
    return (
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
  });
}
