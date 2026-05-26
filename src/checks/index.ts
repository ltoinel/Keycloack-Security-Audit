import type { Check } from "../types.js";
import { realmCheck } from "./realm.js";
import { clientsCheck } from "./clients.js";
import { keysCheck } from "./keys.js";
import { usersCheck } from "./users.js";
import { tlsCheck } from "./external/tls.js";
import { headersCheck } from "./external/headers.js";
import { endpointsCheck } from "./external/endpoints.js";
import { wellKnownCheck } from "./external/wellKnown.js";
import { versionCheck } from "./external/version.js";
import { cveCheck } from "./external/cve.js";

/** All available checks. */
export const allChecks: Check[] = [
  // White-box (Admin API)
  realmCheck,
  clientsCheck,
  keysCheck,
  usersCheck,
  // Black-box (external)
  tlsCheck,
  headersCheck,
  endpointsCheck,
  wellKnownCheck,
  versionCheck,
  cveCheck,
];

export const whiteBoxChecks = allChecks.filter((c) => c.mode === "white");
export const blackBoxChecks = allChecks.filter((c) => c.mode === "black");
