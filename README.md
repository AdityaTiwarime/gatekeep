# GateKeep

An **OpenID Connect identity provider** and an **authenticating reverse proxy**, written in Go using only the standard library (no third-party modules).

The IdP signs people in with the authorization code flow and **PKCE**, issues **RS256 JWTs**, rotates its signing keys and publishes them as a **JWKS**. The proxy sits in front of any HTTP backend, terminates **TLS**, validates every token against the JWKS, enforces role rules per path and hands the backend a trusted identity.

```
 browser / client                      GateKeep                              your app
 ────────────────        ┌──────────────────────────────────┐        ──────────────────
  1. /authorize  ──────► │ IdP   login · PKCE · codes        │
  2. /token      ──────► │       JWT signing · key rotation  │──── /jwks.json ───┐
                         │       refresh rotation · revoke   │── revocation feed ┤
                         └──────────────────────────────────┘                   ▼
  3. GET /api/x  ──TLS──► Proxy  strip spoofed headers → verify JWT (JWKS cache) → check
     Bearer <JWT>                revocation list → check role → X-Auth-User/Roles ──► backend
```

## What it does

**Identity provider** (`internal/idp`)
- Authorization code flow with **mandatory PKCE (S256)**; `plain` and missing challenges are refused
- Exact `redirect_uri` matching; errors for unknown clients are shown on the IdP's own page, never redirected
- `state`, `nonce` and the RFC 9207 `iss` parameter on the redirect (mix-up attack protection)
- Single-use authorization codes (60 s). A code used twice revokes every token issued from it
- **Rotating refresh tokens with reuse detection**: each refresh token works once; replaying an old one revokes the whole session (the "token family")
- **Token revocation** (RFC 7009), `/userinfo`, discovery document, JWKS
- Passwords hashed with **PBKDF2-HMAC-SHA256** (210,000 iterations), constant-time comparison, same timing for unknown users, **lockout after 5 failures**
- Refresh tokens are stored only as SHA-256 hashes

**Signing keys** (`internal/keys`)
- RSA-2048 keys; `kid` is the key's SHA-256 thumbprint
- **Key rotation** with a grace period: the retired public key stays in the JWKS until every token it signed has expired, then it is dropped

**Proxy** (`internal/proxy`)
- Strict JWT validation: algorithm pinned to RS256 (blocks `alg: none` and HS256 **key confusion**), `kid` required, `exp` required, issuer and audience checked, **clock-skew leeway** on `exp`/`nbf`/`iat`
- JWKS cache that picks up rotated keys by itself, but refetches **at most once per interval** so random-`kid` tokens can't flood the IdP
- Revocation list pulled from the IdP every few seconds
- **Deletes client-supplied identity headers** (`X-Auth-User`, `X-Remote-User`, ...) and `X-Forwarded-*` before setting its own, so callers can't impersonate anyone
- Role rules per path prefix (`/admin=admin`, `/health=public`); 401/403 with proper `WWW-Authenticate` headers
- Does not forward the raw bearer token to the backend unless asked to
- Structured JSON logs (method, path, status, user, latency; rejection reasons are logged, not returned)

**PKI / TLS** (`internal/pki`)
- Generates a private CA (path length 0) and **X.509** server certificates with SANs
- Server TLS config: **TLS 1.2 minimum** (1.3 preferred), forward-secret AEAD cipher suites only

## Run it

```bash
make demo            # everything on :8080: IdP at /idp, proxy at /api, demo page at /
```

Open http://localhost:8080 and sign in as `alice` / `alice-demo-pass` (user) or `bob` / `bob-demo-pass` (user, admin). The page lets you call the API, tamper with tokens, rotate keys, refresh, replay refresh tokens and revoke.

Separate processes with TLS:

```bash
make build
./bin/gatekeep certs -out certs -hosts localhost,127.0.0.1
export GATEKEEP_INTERNAL_SECRET=$(openssl rand -hex 32)
./bin/gatekeep idp   -addr :9000 -issuer http://localhost:9000 -client "cli=https://localhost:8443/"
./bin/gatekeep proxy -addr :8443 -upstream http://localhost:8080 -issuer http://localhost:9000 \
                     -tls-cert certs/server.pem -tls-key certs/server-key.pem \
                     -rule /health=public -rule /admin=admin
curl --cacert certs/ca.pem -H "Authorization: Bearer $TOKEN" https://localhost:8443/
```

## Tests

```bash
make race    # 62 test cases, race detector on
make fuzz    # fuzzes the JWT parser
make e2e     # starts the demo and walks the whole flow with curl + openssl (scripts/demo.sh)
```

The tests cover the failure modes rather than just the happy path:

| Area | Cases |
|---|---|
| Token parsing | malformed and oversized tokens, bad base64/JSON, `alg: none`, HS256 key confusion, missing/unknown `kid`, tampered payload, foreign signing key |
| Time | expired, inside vs. outside the clock-skew leeway, `nbf` and `iat` in the future, missing `exp` |
| Claims | wrong issuer, wrong audience, audience lists |
| Keys | rotation grace period, retired key removal, JWK round trip, rejecting EC/HS256/1024-bit keys, concurrent signing during rotation |
| IdP | full code + PKCE flow, wrong verifier, expired code, code replay, unregistered redirect URI, missing/plain PKCE, lockout, refresh rotation, refresh reuse, revocation, confidential clients |
| Proxy | identity reaches backend, spoofed headers stripped, 401/403 cases, clock skew, revocation, key rotation pickup, unknown-`kid` flood, 100 concurrent requests |
| TLS | handshake with our CA, untrusted CA rejected, TLS 1.1 refused |

## Build and package

```bash
make cross   # static binaries: linux amd64/arm64, windows amd64 (.exe), darwin arm64
make deb     # dist/gatekeep_<version>_amd64.deb with a hardened systemd unit
make docker  # distroless, non-root image
```

## Layout

```
cmd/gatekeep        CLI: certs | idp | proxy | demo, plus the demo web client
internal/jwt        RS256 sign/verify with strict validation
internal/keys       key manager, rotation, JWKS
internal/idp        OIDC provider
internal/proxy      authenticating reverse proxy + JWKS cache
internal/pki        CA, certificates, TLS config
internal/revoke     revocation list
scripts/            demo.sh (curl walkthrough), package-deb.sh
```

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats considered and the trade-offs made.

## Limits

This is a learning and portfolio project, not a production IdP. State (codes, refresh tokens, sessions) is in memory, so a restart signs everyone out and a single instance is assumed. Users are a fixed demo list. SAML 2.0 and directory (LDAP/Active Directory) back-ends are not implemented.
