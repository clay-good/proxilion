# Configuration reference

> Authoritative list of every operator-facing configuration input the
> **proxy** reads, with type, default, source precedence, and the security
> note that matters in production. This is the `production-readiness.md` PR-13
> config-reference deliverable.
>
> **This file is drift-gated.** [`crates/proxy/tests/config_docs.rs`](../../crates/proxy/tests/config_docs.rs)
> scans the proxy source for every `env::var(...)` / `secret_env(...)` read and
> fails the build if any variable it finds is not documented here — so a new
> setting cannot ship without an entry. The same test asserts every
> `FileConfig` field is present in
> [`config/proxilion.example.toml`](../../config/proxilion.example.toml).

## How configuration is layered

The proxy resolves each value through four layers, **last writer wins**
([`config.rs`](../../crates/proxy/src/config.rs) — `Config::load`):

```text
built-in defaults  →  TOML file  →  PROXILION_* env vars  →  programmatic overrides
                      (PROXILION_CONFIG_FILE)               (embed / tests only)
```

- A `PROXILION_BIND_ADDR` env var always beats the `bind_addr` TOML line,
  which always beats the built-in default.
- The TOML file is loaded only when `PROXILION_CONFIG_FILE` points at it.
  Unknown TOML keys are rejected at boot (`#[serde(deny_unknown_fields)]`) — a
  typo surfaces as `config file <path>: parse: ...`, never a silent default.
- TOML field names mirror the env var with the `PROXILION_` prefix dropped and
  snake_cased: `bind_addr` ⇔ `PROXILION_BIND_ADDR`. The Google / `DATABASE_URL`
  vars keep their conventional names (no `PROXILION_` prefix) in both layers.
- Malformed numeric / enum values **leave the prior layer's value intact**
  rather than silently downgrading (e.g. a bad `PROXILION_TLS_MIN_VERSION`
  never weakens the floor; a bad `PROXILION_RATE_LIMIT_PER_SEC` never disables
  the limiter). `0` is an explicit, honored *disable* sentinel on the edge
  caps.

## Secret sourcing — the `*_FILE` convention

Every secret-bearing variable below marked **secret** can be sourced from a
mounted file instead of the process environment: set `<VAR>_FILE` to a path and
the proxy reads the secret from that file (trailing newline trimmed), in
**preference** to the direct variable (`secret_env` in
[`config.rs`](../../crates/proxy/src/config.rs)). This keeps secrets out of
`/proc/<pid>/environ`, crash dumps, and `docker inspect`, and lets you back the
mount with the External Secrets Operator, Vault, or a cloud-KMS-backed
Kubernetes `Secret`. If `<VAR>_FILE` is set but unreadable, the proxy falls
back to `<VAR>` (the missing-secret error then surfaces at the specific
consumer, which is more actionable than a generic boot failure).

The `*_FILE`-capable variables are: `DATABASE_URL_FILE`,
`PROXILION_TOKEN_ENCRYPTION_KEY_FILE`, `GOOGLE_CLIENT_SECRET_FILE`,
`PROXILION_SIEM_HMAC_KEY_FILE`, `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY_FILE`.

See [key-inventory.md](key-inventory.md) for the per-secret classification
(algorithm, length, blast radius, rotation).

---

## Network & TLS

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_BIND_ADDR` | `bind_addr` | `SocketAddr` | `0.0.0.0:8443` | Listen address for the agent-facing ingress. |
| `PROXILION_TLS_CERT` | `tls_cert_path` | path | `./certs/dev.crt` | PEM cert. Required to exist unless `dev_mode`. cert-manager owns this in the Helm path. |
| `PROXILION_TLS_KEY` | `tls_key_path` | path | `./certs/dev.key` | PEM private key. Required to exist unless `dev_mode`. |
| `PROXILION_TLS_MIN_VERSION` | `tls_min_version` | `1.2` \| `1.3` | `1.2` | Minimum ingress TLS version. rustls/aws-lc-rs never negotiates below 1.2 structurally; set `1.3` to additionally refuse 1.2 (PR-4). Helm `proxy.tls.minVersion`. |
| `PROXILION_PUBLIC_URL` | `proxy_base_url` | URL | `https://localhost:8443` | The proxy's own public base URL, handed to upstream OAuth as `redirect_uri`. **Must** match the URI registered with the IdP/Google. |
| `PROXILION_DEV` | `dev_mode` | bool (`1`/`true`) | `false` | Dev escape hatch: self-issues a cert at the paths above if absent. **Never set in production.** |
| `PROXILION_TRUSTED_PROXIES` | `trusted_proxies` | comma-sep IPs / list | empty | Direct-peer IPs trusted to set `X-Forwarded-For`. The rate limiter believes the forwarded chain (walked right-to-left) **only** when the TCP peer is listed; otherwise the socket peer is used. Default empty = trust nothing (PR-2/PR-4). Helm `proxy.trustedProxies`. |

## Datastore

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `DATABASE_URL` | `database_url` | URL | none | Postgres connection string. Optional in dev (no persistence); **required** in production. **secret** (`*_FILE`-capable — may carry a password). |

## Upstream services

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_TRUST_PLANE_URL` | `trust_plane_url` | `http(s)://` URL | `http://trust-plane:8080` | Where PCA mint/verify round-trips go. Validated `http(s)://` at boot. mTLS recommended (see [tls-mtls-matrix.md](tls-mtls-matrix.md)). |
| `PROXILION_FEDERATION_BRIDGE_URL` | `federation_bridge_url` | `http(s)://` URL | `http://federation-bridge:8081` | Federation bridge endpoint for the `bridge_callback` path. Validated `http(s)://` at boot. |

## Federation & boot safety (PR-1)

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_ENV` | `environment` | `development` \| `staging` \| `production` | `development` | Deployment environment. A **protected** env (`staging`/`production`) refuses to boot while the insecure federation stub is active. Unrecognized values leave the prior value intact (never silently downgrade a protected env). |
| `PROXILION_INSECURE_BRIDGE_STUB` | `insecure_bridge_stub` | bool | `true` | Whether the payload-only federation stub (no signature verification) is active — the only federation path until PR-1's verified-issuance rewiring lands. `true` + protected `PROXILION_ENV` ⇒ **boot refusal** (`Config::federation_boot_refusal`). Leave `true` in dev; the production guard is the safety net. |

## Token encryption & Google OAuth

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_TOKEN_ENCRYPTION_KEY` | `token_encryption_key_hex` | 64 hex chars | none | AES-256-GCM key encrypting upstream OAuth refresh tokens at rest. Exactly 64 hex chars (32 bytes), validated at boot; `openssl rand -hex 32`. **secret** (`*_FILE`-capable). Scrubbed from memory on drop. |
| `GOOGLE_CLIENT_ID` | `google_client_id` | string | none | Google OAuth client id for the Drive/Gmail/Calendar adapters. |
| `GOOGLE_CLIENT_SECRET` | `google_client_secret` | string | none | Google OAuth client secret. **secret** (`*_FILE`-capable). |
| `GOOGLE_AUTH_URL` | — | URL | `https://accounts.google.com/o/oauth2/v2/auth` | Authorization endpoint override. Defaulted; override only to point at a mock IdP in tests. |
| `GOOGLE_TOKEN_URL` | — | URL | `https://oauth2.googleapis.com/token` | Token endpoint override. Defaulted; test/mock override only. |
| `GOOGLE_API_BASE` | — | URL | none (real `googleapis.com`) | Drive/Gmail/Calendar API base override. Test/mock override only. |

## Policy

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_POLICY_PATH` | `policy_path` | path | none | Layer-B policy YAML. Unset ⇒ empty policy set ⇒ everything defaults **Allow**. The bundled `config/policy.yaml` is the right compose starting point. |
| `PROXILION_CUSTOMER_DOMAIN` | `customer_domain` | string | `example.com` | Substituted for `${customer_domain}` in policy `required_ops` templates. |

## Observability

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_LOG_FORMAT` | `log_format` | `json` \| `pretty` | `json` | `json` for structured ingestion (ELK/Loki/Datadog); `pretty` for local dev. |

## Action stream (NATS) — spec.md §3.1

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_NATS_URL` | `nats_url` | URL | none (disabled) | When set, every persisted `action_event` is fanned out to NATS on `<prefix>.<vendor>.<action>`. Postgres remains the system of record — NATS is best-effort live fan-out. |
| `PROXILION_NATS_SUBJECT_PREFIX` | `nats_subject_prefix` | string | `actions` | Subject prefix for the fan-out. |

## SIEM forwarder — spec.md §3.3

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_SIEM_WEBHOOK_URL` | `siem_webhook_url` | URL | none (disabled) | When set, every persisted `action_event` is POSTed with an HMAC-signed body. |
| `PROXILION_SIEM_HMAC_KEY` | `siem_hmac_key_hex` | hex | none | HMAC key for the `X-Proxilion-Signature` header. Required when the SIEM URL is set. **secret** (`*_FILE`-capable). Scrubbed on drop. |
| `PROXILION_SIEM_BATCH_SIZE` | `siem_batch_size` | int | none / `1` (per-event) | When `> 1`, the forwarder batches up to N events per POST to amortize TLS overhead. |
| `PROXILION_SIEM_BATCH_MAX_AGE_SECS` | `siem_batch_max_age_secs` | int | `5` | Max delay before a partially-filled batch is flushed (clamped to ≥ 1). |

## Blocked-action webhook — ui-less-surfaces.md §10.3

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_BLOCKED_WEBHOOK_URL` | `blocked_webhook_url` | URL | none | First-boot / no-DB fallback for the blocked-action notifier. Once `notifier_config` is set via `proxilion-cli notifier set-webhook`, the DB row wins. |
| `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY` | `blocked_webhook_hmac_key_hex` | hex | none | HMAC key for the blocked-action webhook. **secret** (`*_FILE`-capable). Scrubbed on drop. |

## Approvals (Slack modal — ui-less-surfaces.md)

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_SLACK_BOT_TOKEN` | — | `xoxb-…` | none | Bot token for the Slack `views.open` approval modal. Unset/empty ⇒ the modal flow is skipped (the incoming-webhook direct-commit path is unchanged — the modal is purely additive). **secret.** |
| `PROXILION_SLACK_API_BASE` | — | URL | `https://slack.com/api` | Slack Web API base. Override only to point `views.open` at a mock server in tests. |

## Operator auth — ui-less-surfaces.md §4.4

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_DISABLE_OPERATOR_AUTH` | `operator_auth_enforced` (inverse) | bool (`1`/`true`) | unset ⇒ **enforced** | Set to disable the `pxl_operator_*` bearer requirement on `/api/v1/*`. **Local dev only — never in production.** (TOML key `operator_auth_enforced = true` is the positive form.) |

## Edge resource caps — production-readiness.md PR-2

Each cap accepts `0` as an explicit *disable* sentinel.

| Env var | TOML key | Type | Default | Reject status |
|---|---|---|---|---|
| `PROXILION_MAX_REQUEST_BODY_BYTES` | `max_request_body_bytes` | bytes | `10485760` (10 MiB) | `413` before any body is buffered |
| `PROXILION_REQUEST_TIMEOUT_SECS` | `request_timeout_secs` | secs | `30` | `408` (adapter routes; SSE/streaming exempt) |
| `PROXILION_RATE_LIMIT_PER_SEC` | `rate_limit_per_sec` | req/s | `50` | `429` + `Retry-After` |
| `PROXILION_RATE_LIMIT_BURST` | `rate_limit_burst` | tokens | `100` | (bucket capacity for the limiter above) |
| `PROXILION_MAX_CONCURRENT_REQUESTS` | `max_concurrent_requests` | in-flight | `1024` | `503` (load-shed, never a queue) |

Every rejection increments `proxilion_ingress_rejections_total{reason}`.

## Meta & lifecycle

| Env var | TOML key | Type | Default | Notes |
|---|---|---|---|---|
| `PROXILION_CONFIG_FILE` | — | path | none | Path to the TOML config file. Read by `Config::load` to select the file layer; not itself a TOML field. |
| `PROXILION_DEMO` | — | `1`/`0` | unset ⇒ on iff `action_events` is empty | Demo-mode seeding. `1` forces on, `0` forces off. Development only. |

## FD / ulimit (deployment, not an env var)

The proxy holds one file descriptor per in-flight connection plus the DB pool
and upstream client sockets. Size the process `nofile` ulimit above
`PROXILION_MAX_CONCURRENT_REQUESTS` + DB-pool + headroom (a `65536` soft limit
is the usual floor). In Kubernetes this is the node/runtime default; for bare
`systemd`, set `LimitNOFILE=65536`. The concurrency cap (`503` load-shed) is the
in-process backstop, but the OS limit must sit above it so the cap — not
`EMFILE` — is what sheds.

## CLI / test-only variables (not proxy config)

These are read by `proxilion-cli` or the test harness, not the proxy's
config loader, and are listed for completeness:

| Var | Read by | Purpose |
|---|---|---|
| `DATABASE_URL` | `proxilion-cli` | Same Postgres URL the CLI's admin commands connect with. |
| `PROXILION_CUSTOMER_DOMAIN` | `proxilion-cli` | Default `${customer_domain}` for `policy simulate`. |
| `EDITOR` / `VISUAL` | `proxilion-cli` | Editor selection for interactive edit commands. |
| `USER` | `proxilion-cli` | Default actor label on CLI-issued audit rows. |
| `NO_COLOR` | `proxilion-cli` | Disable ANSI color in CLI output ([no-color.org](https://no-color.org)). |
| `PROXILION_TEST_DATABASE_URL` | test harness | Opt-in Postgres URL for the DB-backed test lane (CI sets it). |

## Helm values mapping

The Helm chart ([`deploy/helm/proxilion`](../../deploy/helm/proxilion)) renders
these into the proxy Deployment's env. The non-obvious mappings:

| Helm value | Env var |
|---|---|
| `proxy.tls.minVersion` | `PROXILION_TLS_MIN_VERSION` |
| `proxy.trustedProxies` | `PROXILION_TRUSTED_PROXIES` |
| `proxy.publicUrl` | `PROXILION_PUBLIC_URL` |
| `proxy.env` | `PROXILION_ENV` |

Secrets (`DATABASE_URL`, `PROXILION_TOKEN_ENCRYPTION_KEY`,
`GOOGLE_CLIENT_SECRET`, the HMAC keys) are sourced from a Kubernetes `Secret`;
prefer the `*_FILE` mount form backed by the External Secrets Operator over
plaintext env. See the chart `README.md` and [key-inventory.md](key-inventory.md).
