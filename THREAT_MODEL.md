# Threat model

What GateKeep defends against, how, and what it deliberately does not.

## Assets
- Users' passwords and sessions
- Signing keys (whoever has them can mint any identity)
- The backend's trust in the `X-Auth-*` headers

## Threats and controls

| Threat | Control | Where |
|---|---|---|
| Stolen authorization code (logs, referrer, malicious app on the same device) | PKCE S256 is mandatory for every client; codes are single-use and expire in 60 s; a replayed code revokes everything it produced | `idp/server.go` exchangeCode |
| Open redirect / code sent to an attacker's URL | Exact `redirect_uri` match; unknown client or URI is answered on the IdP's own page, never redirected | parseAuthRequest |
| CSRF on the client callback | `state` is required by the client and checked | `web/app.js` finishLogin |
| IdP mix-up | RFC 9207 `iss` on the redirect, checked by the client | authorizeSubmit, app.js |
| ID token replay | `nonce` bound into the ID token and checked | issue, app.js |
| Stolen refresh token | Refresh tokens rotate on every use; reuse of a spent one revokes the whole family, including the legitimate user's tokens, forcing a fresh login | exchangeRefresh |
| Database/memory dump of refresh tokens | Only SHA-256 hashes are stored | hashToken |
| Forged token: `alg: none`, HS256 with the public key as secret | Algorithm pinned to RS256 regardless of the header | `jwt.Parse` |
| Tampered claims (e.g. adding `admin`) | Signature checked before any claim is read | `jwt.Parse` |
| Token from another issuer or for another API | `iss` and `aud` checked | proxy Config |
| Clock drift between machines | Configurable leeway (30 s) on `exp`, `nbf`, `iat`; certificates back-dated 5 minutes | jwt, pki |
| Header spoofing (`X-Auth-User: admin`) | Proxy deletes all identity headers and `X-Forwarded-*` from the client before setting its own; the backend must only be reachable through the proxy | proxy.handle |
| DoS via random `kid` values | JWKS refetch at most once per interval; tokens over 8 KB rejected before decoding | JWKSCache, jwt |
| Weak keys injected into the JWKS | JWKs that are not RSA/RS256/sig or are under 2048 bits are ignored | `keys.ParseJWK` |
| Password guessing | PBKDF2 210k iterations; lockout after 5 failures in 5 minutes per username | users.go |
| Username enumeration | Same message and same hashing cost for unknown users | authorizeSubmit |
| Token probing via revocation endpoint | Always 200 (RFC 7009) | revoke |
| Clickjacking the login page | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'` | securityHeaders |
| XSS in the demo client | Strict CSP (`default-src 'self'`), all server data rendered with `textContent` | web/ |
| Signing key compromise | Keys rotate on a schedule; a key can be rotated out immediately and disappears from the JWKS after the grace period | keys |
| Downgrade / weak TLS | TLS 1.2 minimum, ECDHE + AEAD suites only | `pki.ServerTLS` |

## Trade-offs

- **Stateless validation vs. instant revocation.** The proxy verifies tokens locally (fast, no IdP call per request) and pulls a revocation list every few seconds. A revoked token can still pass for up to one poll interval. Short access-token lifetimes (5–10 min) bound the damage further. Introspecting every request would close the gap at the cost of latency and an IdP dependency on every call.
- **Rotation grace period** must be at least the access-token lifetime, or tokens signed just before a rotation would fail early. GateKeep uses 3× the access TTL.
- **Refresh-token reuse detection can log out the real user** when the attacker uses the stolen token first. That is intended: it turns a silent compromise into a visible one.
- **Lockout per username** can be abused to lock someone out. A production system would add per-IP limits and CAPTCHA/step-up instead of a hard lock.

## Out of scope
Persistent storage and multi-instance state, MFA, consent screens, dynamic client registration, SAML 2.0, LDAP/Active Directory back-ends, HSM/KMS-backed keys.
