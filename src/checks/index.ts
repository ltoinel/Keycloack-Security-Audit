import type { Check } from "../types.js";
import { realmCheck } from "./whitebox/realm.js";
import { clientsCheck } from "./whitebox/clients.js";
import { keysCheck } from "./whitebox/keys.js";
import { usersCheck } from "./whitebox/users.js";
import { tlsCheck } from "./blackbox/tls.js";
import { headersCheck } from "./blackbox/headers.js";
import { cookiesCheck } from "./blackbox/cookies.js";
import { hardeningCheck } from "./blackbox/hardening.js";
import { endpointsCheck } from "./blackbox/endpoints.js";
import { jwksCheck } from "./blackbox/jwks.js";
import { wellKnownCheck } from "./blackbox/wellKnown.js";
import { versionCheck } from "./blackbox/version.js";
import { cveCheck } from "./blackbox/cve.js";

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
  cookiesCheck,
  hardeningCheck,
  endpointsCheck,
  jwksCheck,
  wellKnownCheck,
  versionCheck,
  cveCheck,
];

export const whiteBoxChecks = allChecks.filter((c) => c.mode === "white");
export const blackBoxChecks = allChecks.filter((c) => c.mode === "black");
