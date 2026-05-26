import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";
import { detectKeycloakVersion } from "./detectVersion.js";

export const versionCheck: Check = {
  name: "version",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const version = await detectKeycloakVersion(ctx);

    return [
      finding("version.detected", {
        resource: ctx.baseUrl,
        severity: version ? "low" : "info",
        status: version ? "warn" : "skipped",
        detail: version
          ? `Likely version detected: "${version}".`
          : "Version not detected passively (good sign for stealth).",
        // No recommendation when the version was not detected.
        ...(version ? {} : { recommendation: undefined }),
      }),
    ];
  },
};
