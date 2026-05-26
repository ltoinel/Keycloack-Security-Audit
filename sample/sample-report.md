# Audit Report — Keycloak Security Audit

- **Target**: https://auth.example.com
- **Realm**: master
- **Mode**: all
- **Date**: 2026-05-26T10:00:00.000Z

## Score: 66/100

**Risk exposure**: 34 weighted points (impact × likelihood, score = 100 − risk).

| Critical | High | Medium | Low | ✅ Pass | ⚠️ Warn | ❌ Fail |
|---|---|---|---|---|---|---|
| 0 | 2 | 4 | 2 | 21 | 6 | 3 |

## Top risks

| # | Risk | Score | Finding | Category |
|---|---|---|---|---|
| 1 | High | 12 | Implicit Flow enabled | Clients |
| 2 | Medium | 6 | MFA coverage (OTP/WebAuthn) | User accounts |
| 3 | Medium | 5 | CVE-2024-10492 — Path Traversal via External Control of File Name | CVE / Known vulnerabilities |
| 4 | Medium | 5 | CVE-2024-9666 — Proxy header handling Denial-of-Service (DoS) | CVE / Known vulnerabilities |
| 5 | Low | 2.5 | Refresh token revocation / rotation | Realm |

## Clients

### ❌ Implicit Flow enabled _(high)_
- **Resource**: `legacy-spa`
- Client "legacy-spa" allows the Implicit Flow (token exposed in the URL).
- 🎯 **Risk**: High (12) — impact high × likelihood confirmed
- 💡 Disable the Implicit Flow and use the Standard Flow + PKCE.
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients>

### ✅ PKCE on public client
- **Resource**: `spa-public`
- PKCE S256 enforced on "spa-public".
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients>

## User accounts

### ⚠️ MFA coverage (OTP/WebAuthn) _(high)_
- **Resource**: `master`
- 2/15 probed account(s) without 2FA (no OTP nor WebAuthn) (master realm = admin accounts): ci-bot, backup-admin.
- 🎯 **Risk**: Medium (6) — impact high × likelihood potential
- 💡 Require OTP/MFA for all administrators of the master realm (required action or auth flow).

### ✅ Predictable admin account name
- **Resource**: `master`
- No trivial administrative account name detected.

### ✅ Disabled accounts present
- **Resource**: `master`
- 3 disabled account(s) — consider purging obsolete accounts.

## CVE / Known vulnerabilities

### ❌ CVE-2024-10492 — Path Traversal via External Control of File Name _(medium)_
- **Resource**: `keycloak 24.0.1`
- Version 24.0.1 is within the vulnerable range ">= 0, < 24.0.8" (org.keycloak:keycloak-services).
- 🎯 **Risk**: Medium (5) — impact medium × likelihood confirmed
- 💡 Upgrade to 24.0.8 or later.
- 🔗 <https://github.com/advisories/GHSA-5545-r4hg-rj4m>

### ❌ CVE-2024-9666 — Proxy header handling Denial-of-Service (DoS) _(medium)_
- **Resource**: `keycloak 24.0.1`
- Version 24.0.1 is within the vulnerable range ">= 0, < 24.0.8" (org.keycloak:keycloak-services).
- 🎯 **Risk**: Medium (5) — impact medium × likelihood confirmed
- 💡 Upgrade to 24.0.8 or later.
- 🔗 <https://github.com/advisories/GHSA-jgwc-jh89-rpgq>

## Realm

### ⚠️ Refresh token revocation / rotation _(medium)_
- **Resource**: `master`
- revokeRefreshToken = false.
- 🎯 **Risk**: Low (2.5) — impact medium × likelihood potential
- 💡 Enable refresh token revocation (rotation) to limit replay attacks.
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ SSL/HTTPS required
- **Resource**: `master`
- sslRequired = "all".
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ Brute-force protection
- **Resource**: `master`
- Enabled (failureFactor=5).
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ Access token lifespan
- **Resource**: `master`
- accessTokenLifespan = 300s.
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ Content-Security-Policy
- **Resource**: `master`
- contentSecurityPolicy = "frame-src 'self'; frame-ancestors 'self'; object-src 'none';".
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ Password policy
- **Resource**: `master`
- Policy: "length(12) and notUsername and digits(1)" (min length = 12).
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

### ✅ Email verification
- **Resource**: `master`
- verifyEmail = true.
- 🔗 <https://www.keycloak.org/docs/latest/server_admin/>

## HTTP Headers

### ⚠️ Strict-Transport-Security (HSTS) _(medium)_
- **Resource**: `https://auth.example.com`
- Header missing from the response.
- 🎯 **Risk**: Low (2.5) — impact medium × likelihood potential
- 💡 Add HSTS with max-age >= 31536000 (1 year).

### ✅ X-Frame-Options
- **Resource**: `https://auth.example.com`
- Present: "SAMEORIGIN".

### ✅ Content-Security-Policy
- **Resource**: `https://auth.example.com`
- Present: "frame-ancestors 'self'; default-src 'self'".

### ✅ X-Content-Type-Options
- **Resource**: `https://auth.example.com`
- Present: "nosniff".

### ✅ Referrer-Policy
- **Resource**: `https://auth.example.com`
- Present: "strict-origin-when-cross-origin".

## OIDC Discovery

### ⚠️ Implicit Flow advertised _(low)_
- **Resource**: `master`
- response_types_supported = [code, none, id_token, token id_token].
- 🎯 **Risk**: Low (0.5) — impact low × likelihood potential
- 💡 Prefer the code flow; the implicit flow stays advertised by default server-side but should be disabled per client.

### ✅ "none" algorithm advertised
- **Resource**: `master`
- Algorithms: RS256, ES256, PS256.

### ✅ PKCE supported
- **Resource**: `master`
- code_challenge_methods_supported = [S256, plain].

## Exposure / Version

### ⚠️ Exposed Keycloak version _(low)_
- **Resource**: `https://auth.example.com`
- Likely version detected: "24.0.1".
- 🎯 **Risk**: Low (0.5) — impact low × likelihood potential
- 💡 Compare this version against published CVEs (see the CVE check) and plan upgrades.
- 🔗 <https://github.com/keycloak/keycloak/security/advisories>

## Exposed endpoints

### ⚠️ Admin console reachable _(info)_
- **Resource**: `https://auth.example.com/admin/master/console/`
- The admin console is publicly reachable. Not blocking if protected by authentication + MFA, but reducing its exposure surface is recommended.
- 💡 Restrict access (IP allowlist / VPN / reverse proxy) in addition to authentication.

### ✅ /metrics endpoint exposed
- **Resource**: `https://auth.example.com`
- Not reachable from the scanner (neither the main port nor management 9000).

### ✅ /health endpoint exposed
- **Resource**: `https://auth.example.com`
- Not reachable from the scanner (neither the main port nor management 9000).

## Keys & Tokens

### ✅ Active signature key
- **Resource**: `master`
- 2 active signature key(s).

### ✅ Token signature algorithm
- **Resource**: `master`
- Active signature keys: RS256, ES256.

## TLS / Network

### ✅ TLS protocol version
- **Resource**: `auth.example.com`
- Negotiated protocol: TLSv1.3.

### ✅ Trusted TLS certificate
- **Resource**: `auth.example.com`
- Valid certificate (expires in 74 days).

---
_Generated by Keycloak Security Audit. This audit is non-exhaustive and does not replace a manual penetration test._