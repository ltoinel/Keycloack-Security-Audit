import tls from "node:tls";
import type { Check, Finding } from "../../types.js";
import { finding } from "../helpers.js";

const CAT = "TLS / Network";

interface TlsInfo {
  protocol: string | null;
  authorized: boolean;
  authError?: string;
  validTo?: string;
  daysToExpiry?: number;
}

function inspectTls(host: string, port: number): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate();
        let daysToExpiry: number | undefined;
        if (cert?.valid_to) {
          daysToExpiry = Math.round(
            (new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000,
          );
        }
        const info: TlsInfo = {
          protocol: socket.getProtocol(),
          authorized: socket.authorized,
          authError: socket.authorizationError?.toString(),
          validTo: cert?.valid_to,
          daysToExpiry,
        };
        socket.end();
        resolve(info);
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS timeout"));
    });
    socket.on("error", reject);
  });
}

export const tlsCheck: Check = {
  name: "tls",
  mode: "black",
  async run(ctx): Promise<Finding[]> {
    const u = new URL(ctx.baseUrl);
    const out: Finding[] = [];

    if (u.protocol !== "https:") {
      out.push(
        finding({
          id: "tls.https",
          title: "HTTPS on the endpoint",
          category: CAT,
          resource: ctx.baseUrl,
          severity: "critical",
          status: "fail",
          detail: "The server is exposed over plaintext HTTP.",
          recommendation: "Serve Keycloak exclusively over HTTPS.",
        }),
      );
      return out;
    }

    const port = u.port ? Number(u.port) : 443;
    let info: TlsInfo;
    try {
      info = await inspectTls(u.hostname, port);
    } catch (err) {
      out.push(
        finding({
          id: "tls.connect",
          title: "TLS connection",
          category: CAT,
          resource: ctx.baseUrl,
          severity: "info",
          status: "error",
          detail: `Unable to inspect TLS: ${
            err instanceof Error ? err.message : String(err)
          }.`,
        }),
      );
      return out;
    }

    // --- Protocol version -------------------------------------------------
    const proto = info.protocol ?? "unknown";
    const weak = proto === "TLSv1" || proto === "TLSv1.1" || proto === "SSLv3";
    out.push(
      finding({
        id: "tls.version",
        title: "TLS protocol version",
        category: CAT,
        resource: u.hostname,
        severity: weak ? "high" : "low",
        status: weak ? "fail" : "pass",
        detail: `Negotiated protocol: ${proto}.`,
        recommendation: "Disable TLS < 1.2; aim for TLS 1.2/1.3 only.",
      }),
    );

    // --- Certificate validity ---------------------------------------------
    out.push(
      finding({
        id: "tls.cert-valid",
        title: "Trusted TLS certificate",
        category: CAT,
        resource: u.hostname,
        severity: info.authorized ? "low" : "high",
        status: info.authorized ? "pass" : "warn",
        detail: info.authorized
          ? `Valid certificate (expires in ${info.daysToExpiry} days).`
          : `Unverified certificate: ${info.authError ?? "unknown"}.`,
        recommendation:
          "Use a certificate issued by a recognized CA and not expired.",
      }),
    );

    // --- Near expiry ------------------------------------------------------
    if (info.daysToExpiry !== undefined && info.daysToExpiry < 30) {
      out.push(
        finding({
          id: "tls.cert-expiry",
          title: "Certificate expiry",
          category: CAT,
          resource: u.hostname,
          severity: info.daysToExpiry < 7 ? "high" : "medium",
          status: "warn",
          detail: `The certificate expires in ${info.daysToExpiry} day(s).`,
          recommendation: "Renew the certificate / automate renewal.",
        }),
      );
    }

    return out;
  },
};
