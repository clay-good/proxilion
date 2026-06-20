# TLS / mTLS matrix per hop

> Hardening reference for **PR-4 — Transport & trust-boundary hardening**
> ([production-readiness.md](../specs/production-readiness.md)). It states,
> for every network hop the proxy participates in, what transport security
> is required, who terminates TLS, the minimum version, whether the
> certificate is verified, and whether mutual TLS (mTLS) is recommended.

Proxilion sits in the synchronous hot path of every agent request and
terminates TLS for untrusted callers. It also makes several outbound calls
that carry **authority** (PCA/CAT issuance to the Trust Plane) or the
**audit stream** (NATS / SIEM). Getting the trust boundary explicit per
hop is the point of this document.

## TLS floor & cipher posture (ingress)

The agent-facing ingress is terminated by **rustls 0.23 with the aws-lc-rs
provider** ([server.rs](../../crates/proxy/src/server.rs) `build_tls_config`).
Key facts an auditor can rely on:

- **Minimum version is TLS 1.2, structurally.** rustls/aws-lc-rs has no
  code path that negotiates SSLv3 / TLS 1.0 / TLS 1.1 — they cannot be
  enabled. The 1.2 floor therefore holds regardless of configuration.
- **TLS 1.3 can be pinned.** Set `PROXILION_TLS_MIN_VERSION=1.3` (Helm:
  `proxy.tls.minVersion: "1.3"`) to additionally refuse TLS 1.2 for a
  hardened deployment. Default is `1.2` (accept 1.2 + 1.3).
- **Cipher suites are rustls defaults — AEAD only.** TLS 1.3:
  `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`,
  `TLS_CHACHA20_POLY1305_SHA256`. TLS 1.2: the ECDHE + AES-GCM /
  ChaCha20-Poly1305 suites. There are **no** CBC, RC4, 3DES, or static-RSA
  suites; rustls does not implement them. This matches the Mozilla
  "Intermediate" profile's intent (no non-AEAD, no renegotiation).
- **ALPN** advertises `h2` then `http/1.1`.

## The matrix

Legend — **Verify**: is the peer certificate fully verified (chain +
hostname)? **mTLS**: is mutual TLS recommended for production?

### Inbound (the proxy terminates)

| Hop | Transport | Min TLS | Terminator | Verify | mTLS | Notes |
|-----|-----------|---------|------------|--------|------|-------|
| agent → proxy | HTTPS | 1.2 (1.3 opt-in) | proxy (rustls) | n/a (server) | optional | Untrusted callers. App-layer authz is the PCA/session, not the transport. Behind an L7 LB, terminate-and-reterminate or passthrough are both supported; if the LB terminates, declare it in `trustedProxies` (see below). |
| operator → proxy (`/admin`, `/api/v1/*`) | HTTPS | 1.2 (1.3 opt-in) | proxy (rustls) | n/a (server) | optional | Same listener; gated by the operator-token bearer tier, not transport. |

### Outbound (the proxy is the client)

| Hop | Transport | Min TLS | Client | Verify | mTLS | Notes |
|-----|-----------|---------|--------|--------|------|-------|
| proxy → Trust Plane | HTTP(S) | 1.2 | reqwest (rustls-tls) | **yes** on HTTPS | **recommended** | Carries authority issuance (`/v1/pca/issue`, CAT). The bundled Helm default is in-cluster `http://` for a single-namespace install; for production put proxy↔Trust-Plane on **mTLS or a service mesh** (the hop mints authority). |
| proxy → upstream SaaS (Google Drive/Gmail/Calendar) | HTTPS | 1.2 | reqwest (rustls-tls) | **yes** | n/a (public CA) | Full chain + hostname verification. No `danger_accept_invalid_*` anywhere in the production crates (CI-enforced — see below). |
| proxy → IdP JWKS / OIDC discovery | HTTPS | 1.2 | reqwest (rustls-tls) | **yes** | n/a (public CA) | PR-1 (federation signature verification). JWKS/discovery fetched over HTTPS only; never plaintext. |
| proxy → NATS (action stream) | TLS / mesh | 1.2 | async-nats | yes (when `tls://`) | **recommended** | Carries the M3 action/killswitch stream. Use `tls://` NATS URLs or a mesh; on a trusted in-cluster network plaintext is tolerated but not recommended. |
| proxy → SIEM webhook | HTTPS | 1.2 | reqwest (rustls-tls) | **yes** | n/a | Body is additionally HMAC-signed (`X-Proxilion-Signature`) so integrity does not rest on TLS alone. |
| proxy → Slack (approvals) | HTTPS | 1.2 | reqwest (rustls-tls) | **yes** | n/a (public CA) | Approval round-trip. |
| proxy → SMTP (email approvals) | STARTTLS / implicit TLS | 1.2 | lettre (tokio1-rustls-tls + rustls-platform-verifier) | **yes** | n/a | Certificate verified via the platform trust store. |

## Outbound verification is CI-enforced

Full certificate verification on every outbound client is a P0 invariant.
The [`tls-cert-verification`](../../.github/workflows/tls-cert-verification.yml)
workflow fails the build if any production crate
(`crates/proxy`, `crates/policy-engine`, `crates/shared-types`) disables
cert/hostname verification, or if the disable is hardcoded unconditionally
anywhere in the tree. The single permitted use of
`danger_accept_invalid_certs` is the `proxilion-cli --insecure` debug flag
(an explicit operator opt-in, like `curl -k`) — it is gated on the flag, so
it can never be on by default.

## Trusted-proxy configuration (single source of truth)

The proxy trusts the `X-Forwarded-For` chain **only** when the direct TCP
peer is a declared front proxy; otherwise it keys rate-limiting on the
socket peer and ignores the forwarded header
([edge.rs](../../crates/proxy/src/edge.rs), PR-2). This is the one place
that decides "who is internal," shared between PR-2's rate-limit keying and
PR-4's trust boundary.

- **Env:** `PROXILION_TRUSTED_PROXIES` — comma-separated literal peer IPs.
- **Helm:** `proxy.trustedProxies` — a list of literal IPs.
- **Default:** empty = **trust nothing**. Never trust XFF blindly.

CIDR ranges are not yet parsed (literal IPs only); a CIDR entry is dropped.
Set the ingress-controller / LB pod IPs explicitly.

## Public-tier routes (no operator auth)

These routes are intentionally reachable without the operator-token bearer
([server.rs](../../crates/proxy/src/server.rs)); everything else under
`/api/v1/*` requires it. Treat this list as the hardening surface:

- `GET /healthz` — readiness/liveness probe (no secrets).
- `GET /metrics` — Prometheus scrape (bind to the metrics network /
  ServiceMonitor; do not expose publicly).
- `GET /admin`, `GET /admin/setup` — server-rendered admin/setup pages
  (the actions they trigger are operator-authed; the page shell is public).
- The OAuth callback + the single mobile approve-landing page.

`/admin` and the SSE/approval surfaces set `Cache-Control: no-store`
(audited). Bind `/metrics` to an internal listener or a ServiceMonitor
scrape, not the public ingress.

## Certificate provisioning

- **Production:** cert-manager in the Helm path. `proxy.ingress.annotations`
  carries `cert-manager.io/cluster-issuer`, and `proxy.tls.existingSecret`
  mounts the issued `tls.crt`/`tls.key`. The chart never generates
  production secret material.
- **Dev only:** `proxy.devCert: true` (or `PROXILION_DEV=1`) generates a
  self-signed cert via `rcgen`. `certs/` + `dev-cert.sh` in the repo are
  dev-only.

## Go-live verification (staging)

Before exposing any IdP-facing route to an untrusted network, run an
external TLS scanner against the staging ingress and confirm the posture
this document claims:

```sh
# No TLS < 1.2, no weak suites, AEAD-only.
testssl.sh --severity HIGH https://<staging-proxy-host>:8443
# or
nmap --script ssl-enum-ciphers -p 8443 <staging-proxy-host>
```

Expected: TLS 1.2 and/or 1.3 only; no SSLv3/TLS1.0/TLS1.1; no CBC/RC4/3DES
suites; certificate chain valid. With `PROXILION_TLS_MIN_VERSION=1.3` the
scanner must show TLS 1.2 **refused**. Record the scan output in the PR-13
production-readiness review.
