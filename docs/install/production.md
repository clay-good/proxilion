# Production deployment guide

> production-readiness.md **PR-13**. The ordered path from nothing to a
> Proxilion you can put in front of a managed agent. Every step links to the
> document that owns the detail — this page is the **sequence and the
> decisions**, not a restatement. Finish with the
> [go-live checklist](../ops/go-live-checklist.md).

**Before you start**, know the two things that will refuse to boot if you get
them wrong, because they are the two that matter most:
`PROXILION_ENV=production` will not start without the verified federation path
configured (§3), and will not start without a stable PIC executor identity
(§4). Both refusals are deliberate — see the sections for why neither is
recoverable after the fact.

## 1. Provision

| Component | Requirement |
|---|---|
| Postgres 16+ | system of record. Size `max_connections` for `pool_size × replicas`. HA + WAL archiving: [backup-restore.md](../ops/runbooks/backup-restore.md) |
| Trust Plane | reachable over TLS (mTLS recommended: [tls-mtls-matrix.md](../ops/tls-mtls-matrix.md)) |
| OIDC IdP | Okta / Azure AD / Google Workspace / any OIDC, publishing a JWKS over HTTPS |
| Kubernetes | the chart assumes ≥ 2 replicas. Sizing and the per-replica arithmetic: [ha-and-scaling.md](../ops/ha-and-scaling.md) |
| NATS, SIEM | optional; the action stream and audit forwarder |

## 2. Secrets

Generate, store in your secret manager, and mount as files — every secret
supports the `<VAR>_FILE` convention, which keeps it out of
`/proc/<pid>/environ` and `docker inspect`:

```bash
openssl rand -hex 32   # PROXILION_TOKEN_ENCRYPTION_KEY
openssl rand -hex 32   # PROXILION_EXECUTOR_KEY
```

Full inventory, blast radius, and rotation: [key-inventory.md](../ops/key-inventory.md).
**Do not put the token-encryption key in the same store as your database
backups** — a backup plus that key is full impersonation of every linked user.

## 3. Federation (the part that makes Proxilion Proxilion)

Point the proxy at your IdP. All three are required together; a partial
configuration is an operator error, never a silent fallback:

| Setting | Value |
|---|---|
| `PROXILION_IDP_ISSUER` | the `iss` your IdP mints, exactly |
| `PROXILION_IDP_AUDIENCE` | the `aud` your IdP mints for Proxilion |
| `PROXILION_IDP_JWKS_URI` | the issuer's JWKS endpoint — **`https://` only** |
| `PROXILION_IDP_ALGORITHMS` | leave at `RS256,ES256` unless your IdP needs otherwise |

Leave `PROXILION_INSECURE_BRIDGE_STUB` unset. It is off by default and a
protected `PROXILION_ENV` refuses to boot with it on: the unsigned
`federation_token` path lets any caller who can reach the callback forge an
arbitrary human principal, which defeats the entire product.

Your IdP must emit a `pic_ops` claim carrying the ops the human holds — that
claim, read only from the signature-verified token, is what seeds PCA_0.

## 4. Executor identity

```
PROXILION_EXECUTOR_KID=proxy-prod-1
PROXILION_EXECUTOR_KEY_FILE=/secrets/executor-key
```

Both, or the proxy refuses to boot in a protected environment. Without them
every replica and every restart registers a *new* executor with the Trust
Plane: nothing stable to revoke if one is compromised, and audit hops
attributed to identities that exist nowhere else. None of that is recoverable
later. Setting only one is worse than neither — two replicas would register
different public keys under the same `kid`.

## 5. Deploy

```bash
helm upgrade --install proxilion deploy/helm/proxilion \
  --set secrets.existingSecret=proxilion-secrets \
  --set proxy.env.environment=production \
  --set proxy.env.idp.issuer=https://acme.okta.com \
  --set proxy.env.idp.audience=proxilion \
  --set proxy.env.idp.jwksUri=https://acme.okta.com/oauth2/v1/keys \
  --set proxy.env.executorKid=proxy-prod-1 \
  --set proxy.image.digest=sha256:...
```

Pin the image by **digest**, not tag, and verify it first:
[verifying-artifacts.md](./verifying-artifacts.md). Chart values reference:
[config-reference.md](../ops/config-reference.md#helm-values-mapping).

## 6. Size the limits

The edge caps are **per replica**, so divide your fleet budget by the replica
count before setting them ([ha-and-scaling.md §2](../ops/ha-and-scaling.md)):

| Setting | Sized against |
|---|---|
| `PROXILION_MAX_CONNECTIONS` | must sit below `ulimit -n`; an idle keep-alive connection costs an FD |
| `PROXILION_MAX_CONCURRENT_REQUESTS` | CPU and DB pool |
| `PROXILION_RATE_LIMIT_PER_SEC` / `_BURST` | per client IP, ×N replicas |
| `PROXILION_TRUSTED_PROXIES` | your ingress's pod IPs — leave empty unless you have one, or `X-Forwarded-For` becomes spoofable |

## 7. Policy

Author the Layer-B bundle and mount it as the ConfigMap the chart renders.
Start in observe mode, read the action stream, then enforce. Policy language:
[spec.md §9](../specs/spec.md).

## 8. Observability

Scrape [ops/prometheus/prometheus.yml](../../ops/prometheus/prometheus.yml),
load [alerts.yml](../../ops/prometheus/alerts.yml), route with
[alertmanager.yml](../../ops/prometheus/alertmanager.yml), import
[grafana/proxilion.json](../../ops/grafana/proxilion.json). SLO definitions:
[slos.md](../ops/slos.md).

The one series that must always read zero is
`proxilion_pca_verify_failures_total`. It pages to a dedicated security
receiver with no grouping delay.

## 9. Verify, then go live

```bash
proxilion-cli --url https://proxy.internal --token "$TOKEN" status
proxilion-cli --url https://proxy.internal --token "$TOKEN" pic verify-sample
```

Then work the [go-live checklist](../ops/go-live-checklist.md). Do not expose
`/oauth/bridge/callback` to an untrusted network before it is signed off.

## Upgrades and rollback

Migrations are forward-only, so image rollback safety comes from the
expand/contract discipline in
[backup-restore.md §5](../ops/runbooks/backup-restore.md). Take a base backup
before any contract migration. Rolling restarts are safe: the chart's
`PodDisruptionBudget` keeps one replica serving, and
`terminationGracePeriodSeconds` outlasts the proxy's 30 s in-process drain.
