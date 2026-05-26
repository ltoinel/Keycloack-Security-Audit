import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parse } from "yaml";
import type { Severity } from "../types.js";

/** Declarative expectation for a rule-based check (e.g. HTTP headers). */
export interface ExpectRule {
  /** Case-insensitive equality. */
  equals?: string;
  /** Case-insensitive regular expression the value must match. */
  regex?: string;
  /** For HSTS: the `max-age` directive must be >= this value. */
  minMaxAge?: number;
}

/**
 * Configurable, per-check metadata loaded from `checks.yaml`. For most checks,
 * status, severity and detail are computed by the check logic. Rule-based
 * checks (HTTP headers) additionally drive their `header`, `severity` and
 * `expect` matcher entirely from the configuration.
 */
export interface CheckMeta {
  title?: string;
  category?: string;
  recommendation?: string;
  references?: string[];
  /** HTTP header to inspect (marks this entry as a header rule). */
  header?: string;
  /** Severity for rule-based checks (HTTP headers). */
  severity?: Severity;
  /** Declarative expectation for the header value. */
  expect?: ExpectRule;
}

/** A fully-resolved HTTP header rule, derived from the configuration. */
export interface HeaderRule {
  id: string;
  header: string;
  severity: Severity;
  expect?: ExpectRule;
}

interface RawCheck extends CheckMeta {
  enabled?: boolean;
}
interface RawConfig {
  modules?: Record<string, boolean>;
  checks?: Record<string, RawCheck | null>;
}

const checks = new Map<string, RawCheck>();
const modules = new Map<string, boolean>();

/** Default config shipped with the tool (resolved relative to this module). */
const DEFAULT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../checks.yaml",
);

/**
 * Loads the check configuration. Resolution order:
 *   1. an explicit `--config` path,
 *   2. `checks.yaml` in the current working directory,
 *   3. the default file shipped with the tool.
 * Returns the path that was actually loaded.
 */
export function loadChecksConfig(explicitPath?: string): string {
  const cwdPath = resolve(process.cwd(), "checks.yaml");
  const path = explicitPath
    ? resolve(explicitPath)
    : existsSync(cwdPath)
      ? cwdPath
      : DEFAULT_PATH;

  const cfg = (parse(readFileSync(path, "utf8")) ?? {}) as RawConfig;

  checks.clear();
  modules.clear();
  for (const [id, meta] of Object.entries(cfg.checks ?? {})) {
    checks.set(id, meta ?? {});
  }
  for (const [name, enabled] of Object.entries(cfg.modules ?? {})) {
    modules.set(name, enabled);
  }
  return path;
}

/** Configurable text/metadata for a check id, or undefined if not configured. */
export function checkMeta(id: string): CheckMeta | undefined {
  return checks.get(id);
}

/** Whether an individual check (finding id) is enabled. Unknown ids default to true. */
export function isCheckEnabled(id: string): boolean {
  const c = checks.get(id);
  return c ? c.enabled !== false : true;
}

/** Whether a whole check module (by its name) is enabled. Unknown modules default to true. */
export function isModuleEnabled(name: string): boolean {
  return modules.get(name) !== false;
}

/** Configured category for an id, falling back to the provided default. */
export function categoryOf(id: string, fallback: string): string {
  return checks.get(id)?.category ?? fallback;
}

/**
 * HTTP header rules declared in the configuration, in file order. Any check
 * entry that defines a `header` field is treated as a header rule, so new
 * header checks can be added in `checks.yaml` without code changes.
 */
export function headerRules(): HeaderRule[] {
  const rules: HeaderRule[] = [];
  for (const [id, meta] of checks) {
    if (meta.header) {
      rules.push({
        id,
        header: meta.header,
        severity: meta.severity ?? "low",
        expect: meta.expect,
      });
    }
  }
  return rules;
}
