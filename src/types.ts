export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "fail" | "warn" | "pass" | "skipped" | "error";

export interface Finding {
  /** Stable check identifier, e.g. "client.implicit-flow" */
  id: string;
  /** Short, human-readable title */
  title: string;
  status: FindingStatus;
  severity: Severity;
  /** Display category in the report */
  category: string;
  /** Explanation of the observed result */
  detail: string;
  /** Remediation recommendation */
  recommendation?: string;
  /** Affected element (client name, realm, endpoint...) */
  resource?: string;
  /** External references (CIS, OWASP, Keycloak docs) */
  references?: string[];
}

export interface CheckContext {
  baseUrl: string;
  realm: string;
  tlsVerify: boolean;
  /** Keycloak version provided manually (CLI/env), bypassing passive detection */
  version?: string;
  /** Present only if Admin API authentication succeeded */
  admin?: AdminApi;
}

export interface AdminApi {
  /** GET on the Admin REST API, path relative to /admin/realms */
  get<T = unknown>(path: string): Promise<T>;
}

/** A check module: receives the context, returns a list of findings. */
export interface Check {
  name: string;
  /** "white" = requires the Admin API, "black" = external test without credentials */
  mode: "white" | "black";
  run(ctx: CheckContext): Promise<Finding[]>;
}

export interface AuditConfig {
  baseUrl: string;
  realm: string;
  tlsVerify: boolean;
  /** Keycloak version provided manually (CLI/env) */
  version?: string;
  adminUser?: string;
  adminPassword?: string;
  adminClientId: string;
  adminClientSecret?: string;
}
