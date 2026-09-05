# ops/

Operator-facing artifacts for running Proxilion.

## Prometheus

The proxy exposes a `/metrics` endpoint on its TLS port. A ready-to-use scrape
config — drop in directly or merge the `proxilion` job into an existing one —
lives in [`prometheus/prometheus.yml`](prometheus/prometheus.yml). The core of
it:

```yaml
scrape_configs:
  - job_name: proxilion
    metrics_path: /metrics
    scheme: https
    tls_config:
      insecure_skip_verify: true   # dev only — see the file for the prod TLS note
    static_configs:
      - targets: ["proxy:8443"]
```

That file also carries an example Alertmanager rule for the one series that must
always read zero (`proxilion_pca_verify_failures_total`).

## Alertmanager

[`prometheus/alertmanager.yml`](prometheus/alertmanager.yml) is a complete
routing config for the alert set: `severity: page` → the on-call pager, the two
security invariants → a separate security receiver with no group wait, and
everything else → the team queue, with inhibitions so one Trust Plane outage
pages once rather than three times. Replace the placeholder routing keys and
webhook URL. `amtool check-config` runs on it in CI. Rationale and the routing
table are in [docs/ops/slos.md](../docs/ops/slos.md#routing).

## Grafana

[`grafana/proxilion.json`](grafana/proxilion.json) is a starter dashboard:
auth attempt rate + rejection share, token-refresh outcomes, PCA cache
hit/miss, **and a PCA verification-failure panel that should always read
zero**. Any non-zero increase there means a tampered PCA was loaded out of
cache or a CAT key rotation hasn't propagated — page someone.

Import: Grafana → Dashboards → New → Import → upload JSON. Choose your
Prometheus datasource.

## Metrics reference

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `proxilion_auth_attempts_total` | counter | `result` (`ok` / `rejected`) | Per request through the bearer middleware. |
| `proxilion_oauth_token_refreshes_total` | counter | `result` (`ok` / `coalesced` / `upstream_err`), `vendor` | Google OAuth refresh flow. `coalesced` is the per-bearer stampede defense. |
| `proxilion_pca_cache_hits_total` | counter | — | `pca_cache` row found locally. |
| `proxilion_pca_cache_misses_total` | counter | — | Miss → 401 (we don't fall back to Trust Plane since upstream has no `GET /v1/pca/{id}` endpoint yet — see spec.md §1.2 deviations). |
| `proxilion_pca_verify_failures_total` | counter | — | CAT signature verification failed. **Must stay 0** in steady state. |

## CLI

```bash
proxilion-cli health
proxilion-cli pca <UUID>
proxilion-cli verify <UUID>   # exits non-zero on a broken chain
```

Pass `--insecure` against a dev TLS cert.
