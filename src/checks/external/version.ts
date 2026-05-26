import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { detectKeycloakVersion } from "./detectVersion.js";

const CAT = "Exposure / Version";

export const versionCheck: Check = {
  name: "version",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const version = await detectKeycloakVersion(ctx);

    return [
      finding({
        id: "version.detected",
        title: "Exposed Keycloak version",
        category: CAT,
        resource: ctx.baseUrl,
        severity: version ? "low" : "info",
        status: version ? "warn" : "skipped",
        detail: version
          ? `Likely version detected: "${version}".`
          : "Version not detected passively (good sign for stealth).",
        recommendation: version
          ? "Compare this version against published CVEs (see the CVE check) and plan upgrades."
          : undefined,
        references: ["https://github.com/keycloak/keycloak/security/advisories"],
      }),
    ];
  },
};
