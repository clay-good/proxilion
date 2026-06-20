# Key & secret inventory

> Reference for **PR-3 — Key management, rotation & in-memory hygiene**
> ([production-readiness.md](../specs/production-readiness.md)). Enumerates
> every secret the **proxy process** holds: purpose, algorithm/length, blast
> radius, source, and in-memory hygiene. Rotation procedures live in the
> PR-6 runbooks (not yet written); this is the classification step.

## What the proxy holds

| Secret | Algorithm / length | Source (env / Helm) | Purpose | Blast radius if leaked | In-memory hygiene |
|--------|--------------------|---------------------|---------|------------------------|-------------------|
| **Token-encryption key** | AES-256-GCM, 32 bytes (64 hex) | `PROXILION_TOKEN_ENCRYPTION_KEY` / secret `token-encryption-key` | Encrypts upstream OAuth access/refresh tokens at rest in Postgres | Decrypt **every** stored upstream OAuth token (full impersonation of every linked user against the SaaS) | Held inside `Aes256Gcm` ([token_cipher.rs](../../crates/proxy/src/crypto/token_cipher.rs)), which zeroizes its key on drop (aes-gcm `zeroize` feature). `TokenCipher` has no `Debug`. |
| **SIEM HMAC key** | HMAC-SHA256, ≥ 16 bytes | `PROXILION_SIEM_HMAC_KEY` / secret `siem-hmac-key` | Signs SIEM webhook bodies (`X-Proxilion-Signature`) | Forge SIEM event signatures (tamper with the audit feed an SOC trusts) | `Zeroizing<Vec<u8>>` — scrubbed on drop; explicit redacting `Debug` ([siem.rs](../../crates/proxy/src/forwarder/siem.rs)). |
| **Blocked-action webhook HMAC key** | HMAC-SHA256, ≥ 16 bytes | `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY` | Signs blocked-action webhook bodies | Forge blocked-action webhook signatures | `Zeroizing<Vec<u8>>` + redacting `Debug` ([webhook.rs](../../crates/proxy/src/notifier/webhook.rs)). |
| **Ingress TLS private key** | cert/key PEM (rustls) | `PROXILION_TLS_KEY` / `proxy.tls.existingSecret` | Terminates agent/operator-facing TLS | Impersonate the proxy endpoint / MITM ingress | Loaded by rustls from a file/secret mount at boot; lives inside the rustls `ServerConfig`. See [tls-mtls-matrix.md](./tls-mtls-matrix.md). |

## What the proxy does NOT hold (clarifications)

- **CAT signing key.** The proxy only fetches and caches the Trust Plane's
  CAT **public** key for *verification*
  ([cat_key.rs](../../crates/proxy/src/pic/cat_key.rs) holds a `PublicKey`).
  The private CAT signing key (Helm `trust-plane-cat-key`, an Ed25519 seed)
  is consumed by the **Trust Plane** workload, not the proxy. Ed25519-dalek's
  `SigningKey` zeroizes on drop where it is held.
- **Operator-token secret.** Operator bearer tokens (`pxl_operator_*`) are
  not stored; only their SHA-256 hash (`BearerHash`,
  [bearer.rs](../../crates/proxy/src/crypto/bearer.rs)) is persisted, and its
  `Debug` truncates to a short prefix. There is no separate pepper/HMAC key —
  the raw bearer is request-scoped and compared by constant-time hash equality.

## Classification

- **Replica-local, DB/secret-backed, zeroized on drop:** token-encryption
  key, SIEM HMAC, blocked-webhook HMAC. Decoded bytes are scrubbed on drop
  (PR-3 memory hygiene, this slice).
- **Verification-only / non-secret in the proxy:** CAT public key.
- **Transport material:** TLS private key (file/secret mount; rotated via
  cert-manager, PR-4).

## Remaining PR-3 work (not in this slice)

The memory-hygiene + inventory steps are done; still open before PR-3 closes:

- **Versioned keys with overlap** (`kid`/version: active + N also-accept
  predecessors) so rotation is add → flip → drain → retire with zero rejected
  in-flight requests. Token-encryption rotation re-encrypts lazily or via a
  one-shot `proxilion-cli` re-wrap command.
- **Production secret sourcing** beyond env: a `*_FILE` convention and
  External Secrets Operator / Vault / cloud-KMS envelope-encryption guidance.
- **Rotation runbooks** (one per key; planned + emergency/compromise),
  landing with PR-6.
