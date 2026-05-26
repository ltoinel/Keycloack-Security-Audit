# Keycloak Security Audit

Security audit tool for **Keycloak** servers. It combines:

- **White-box** — configuration analysis via the **Admin REST API** (realm, clients, signing keys, user accounts).
- **Black-box** — external tests without credentials (TLS, HTTP headers, exposed endpoints, OIDC discovery, version, **known CVEs**).

Output: **HTML**, **Markdown**, **JSON** and **SARIF** (code scanning / SIEM) with a score, severities and recommendations.

> ⚠️ Only audit servers you are **authorized** to test. The checks are designed to be **non-intrusive** (no brute-force attempts and no active user enumeration).

## Installation

```bash
npm install
cp .env.example .env   # then fill in your settings
```

Requires Node.js ≥ 18.17.

## Configuration

Fill in `.env` (see `.env.example`). For white-box, two authentication modes:

1. **Service account** (recommended): `KC_ADMIN_CLIENT_ID` + `KC_ADMIN_CLIENT_SECRET`
   on a confidential client holding the `view-realm` / `view-clients` roles.
2. **Admin account**: `KC_ADMIN_USER` + `KC_ADMIN_PASSWORD` (password grant via `admin-cli`).

Without credentials, only the black-box checks run.

## Usage

```bash
# Full audit (config + external), reading .env
npm run audit

# URL passed directly as an argument (no --url or .env)
npm run audit -- https://auth.example.com --realm prod

# Command-line overrides (--url is equivalent to the positional argument)
npm run audit -- --url https://auth.example.com --realm prod --mode all

# Configuration only (Admin API, requires credentials)
npm run audit -- --url https://auth.example.com --realm prod --mode whitebox

# External tests only (no credentials needed)
npm run audit -- --url https://auth.example.com --realm prod --mode blackbox

# Provide the Keycloak version explicitly (enables CVE correlation when passive detection fails)
npm run audit -- --url https://auth.example.com --kc-version 26.0.5

# Internal lab with a self-signed certificate
npm run audit -- --no-tls-verify

# Choose the output formats
npm run audit -- --format json,sarif
npm run audit -- --format all

# CI integration: non-zero exit on a hard failure (status fail) of severity >= high
# ("warn" never fails CI)
npm run audit -- --fail-on high --format sarif
```

Reports are written to the `reports/` directory by default (override with `-o, --out`).

## Tests

```bash
npm test   # native Node runner, no dependencies: semver, redirect URIs, password policy, scoring
```

> The **CVE** check queries the public GitHub Security Advisories API
> (60 req/h anonymously). Set `GITHUB_TOKEN` to raise this limit. If the version
> cannot be detected passively, pass `--kc-version` (or set `KC_VERSION`) so the
> correlation can still run.

### CLI options

| Option | Description | Default |
|---|---|---|
| `-u, --url` | Keycloak base URL | `KC_BASE_URL` |
| `-r, --realm` | Realm to audit | `KC_REALM` or `master` |
| `-m, --mode` | Scope: `all` \| `whitebox` \| `blackbox` (aliases `white`/`black`) | `all` |
| `-o, --out` | Output directory | `reports` |
| `-f, --format` | `html,md,json,sarif` or `all` (comma-separated list) | `html,md` |
| `--no-tls-verify` | Disable TLS verification | (verifies) |
| `--fail-on` | Failure threshold: `critical`\|`high`\|`medium` | `high` |
| `--kc-version` | Keycloak version for CVE correlation | `KC_VERSION` or passive detection |

## Implemented checks

**White-box** (`src/checks/`): SSL required, brute-force, password policy,
token lifespan, refresh token rotation, self-registration, email verification,
realm CSP · Implicit flow, ROPC, PKCE, redirect URIs, Web Origins CORS, service accounts
on public clients · signing algorithm, key presence/rotation · predictable admin
accounts, MFA coverage (OTP **and** WebAuthn/passkey, sampled), disabled accounts.

**Black-box** (`src/checks/external/`): TLS version/protocol, certificate validity and
expiry, HSTS / X-Frame-Options / X-Content-Type-Options / CSP / Referrer-Policy,
exposed `/metrics` and `/health` endpoints (also probed on the **management port 9000**),
admin console reachability, OIDC discovery (`alg none`, PKCE, implicit), passive version
detection, **CVE correlation** (GitHub Security Advisories, paginated).

## Scoring & risk weighting

Each finding carries a **weighted risk = impact × likelihood**:

- **Impact** comes from the severity — Critical `25`, High `12`, Medium `5`, Low `1`, Info `0`.
- **Likelihood** comes from the status — a `fail` is a confirmed issue (`×1`), a `warn` is
  a potential one (`×0.5`); `pass` / `skipped` / `error` carry no residual risk.

The resulting score maps to a risk level (Critical ≥ 18, High ≥ 9, Medium ≥ 3, Low > 0).
The overall **score = 100 − total risk exposure** (the sum of per-finding risk). All reports
rank findings by risk and surface the **Top risks**; the JSON output exposes a `risk` object
per finding and a `byRisk` / `risk` breakdown in the summary.

## Architecture

Each check implements the `Check` interface (`src/types.ts`) and returns `Finding[]`.
To add a check: create a file in `src/checks/`, export a `Check`, and register it in
`src/checks/index.ts`. No other change is needed.

## Limitations

Automated, **non-exhaustive** audit. It does not replace a manual penetration test and does
not deeply test SAML, federation/IdP, or the clients' application logic. MFA coverage is
**sampled** (50 accounts) and CVE correlation is limited to the 100 most recent GitHub
advisories for Keycloak packages — cross-check with the NVD and the Release Notes.

## License

Released under the [MIT License](LICENSE).
