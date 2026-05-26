/**
 * Version comparison and range evaluation, sufficient for Keycloak versions
 * (major.minor.patch) and the ranges of GitHub advisories.
 */

/** Normalizes "26.0.5-SNAPSHOT" -> [26, 0, 5]. */
function parts(v: string): number[] {
  const clean = v.trim().replace(/^v/, "").split(/[-+]/)[0];
  return clean.split(".").map((n) => Number.parseInt(n, 10) || 0);
}

/** -1 if a<b, 0 if equal, 1 if a>b. */
export function compareVersions(a: string, b: string): number {
  const pa = parts(a);
  const pb = parts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Evaluates a range such as ">= 21.0.0, < 21.1.2" or "< 22.0.10" or "= 18.0.0".
 * Comma-separated constraints are combined with AND.
 */
export function satisfiesRange(version: string, range: string): boolean {
  const constraints = range.split(",").map((c) => c.trim()).filter(Boolean);
  if (constraints.length === 0) return false;

  for (const c of constraints) {
    const m = c.match(/^(>=|<=|>|<|=|==)?\s*(.+)$/);
    if (!m) return false;
    const op = m[1] ?? "=";
    const cmp = compareVersions(version, m[2].trim());
    const ok =
      (op === ">=" && cmp >= 0) ||
      (op === "<=" && cmp <= 0) ||
      (op === ">" && cmp > 0) ||
      (op === "<" && cmp < 0) ||
      ((op === "=" || op === "==") && cmp === 0);
    if (!ok) return false;
  }
  return true;
}
