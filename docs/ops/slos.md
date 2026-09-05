# SLOs, SLIs & error budgets

> The alerting contract for **PR-5** ([production-readiness.md](../specs/production-readiness.md)).
> Defines the service-level indicators and objectives the alert rules in
> [`ops/prometheus/alerts.yml`](../../ops/prometheus/alerts.yml) enforce, the
> rationale and measurement windows, and the routing/runbook mapping.

## Principles

- **Alert on symptoms users feel**, on a multi-window multi-burn-rate basis
  (Google SRE Workbook, "Alerting on SLOs") so a brief blip never pages and a
  real burn always does.
- **A policy block is not an error.** Proxilion *blocking* a disallowed action
  is the product working; availability SLIs count only 5xx/internal failures
  (`proxilion_adapter_upstream_errors_total`), never policy decisions.
- **Every alert names a runbook.** Each rule carries a `runbook_url`
  annotation into [runbooks/](./runbooks/) (authored in PR-6).

## SLOs

| # | SLO | Target | SLI (metric) | Window | Alerts |
|---|-----|--------|--------------|--------|--------|
| 1 | **Request availability** | 99.9% | `1 − upstream_errors / adapter_requests` | 30d rolling | `ProxilionAvailabilityFastBurn` (page), `ProxilionAvailabilitySlowBurn` (ticket) |
| 2 | **Added latency** (proxy overhead) | p99 < 1 ms (alert at 5 ms) | `proxilion_policy_evaluation_duration_seconds{quantile="0.99"}` | 5 m | `ProxilionPolicyEvalLatencyHigh` (ticket) |
| 3 | **Federation / issuance success** | ≥ 99% | `oauth_callback` + `pca_issue` non-`ok` ratio | 15 m | `ProxilionFederationCallbackFailing`, `ProxilionPcaIssueFailing` (page) |
| 4 | **Approval-path liveness** | backlog < 50, no wedge | `proxilion_overrides_pending`, `proxilion_override_latency_seconds` | 30 m | `ProxilionApprovalBacklogGrowing` (ticket) |
| 5 | **Killswitch propagation** | ≤ one request cycle (spec.md M3) | (per-replica cache TTL + NATS fan-out; no direct SLI yet — see note) | — | covered indirectly via Trust Plane / NATS alerts |

### Rationale

- **99.9% availability** (≈ 43 min/month budget) is the right first target for
  a synchronous in-path proxy fronting agent traffic — high enough to be
  meaningful, loose enough to absorb upstream SaaS hiccups the proxy can't
  control. Burn-rate thresholds: fast-burn 14.4× over 1 h (confirmed at 5 m)
  and 6× over 6 h (30 m); slow-burn 3× over 1 d (2 h) and 1× over 3 d (6 h).
- **Sub-ms p99 policy eval** is the spec.md §9 design target; the alert fires
  at 5 ms so normal GC/scheduling jitter stays quiet while a real regression
  (e.g. a pathological policy) pages a ticket.
- **Federation success** gates the whole product (no PCA → no authority); a
  >10% failure ratio over 15 m is a page.

### Killswitch propagation (note)

There is no direct propagation-latency SLI today. Propagation is bounded by
the per-replica `kill_cache` TTL + NATS fan-out (spec.md M3); the
`ProxilionTrustPlaneDown` / `ProxilionNatsPublishFailing` alerts cover the
infrastructure it depends on. A dedicated propagation-latency metric is a
PR-7 (statelessness audit) follow-up.

## Operational alerts (not SLO burn, but page/ticket-worthy)

| Alert | Severity | Condition |
|-------|----------|-----------|
| `ProxilionPcaVerifyFailure` | page | any `pca_verify_failures` increase (tampered PCA / stale CAT key) |
| `ProxilionPicInvariantViolation` | page | any `pic_invariant_violations` increase |
| `ProxilionAuditPersistFailing` | page | audit/action row persistence failing (DB) |
| `ProxilionTrustPlaneDown` | page | `trust_plane_up == 0` |
| `ProxilionEdgeLoadShedding` | ticket | sustained `ingress_rejections{reason=load_shed\|rate_limit}` |
| `ProxilionNatsPublishFailing` / `ProxilionSiemForwardFailing` | ticket | audit/action stream delivery failing |
| `ProxilionPolicyReloadFailing` | ticket | policy hot-reload failed (last-good retained) |
| `ProxilionApprovalBacklogGrowing` | ticket | `overrides_pending > 50` for 30 m |
| `ProxilionCertExpirySoon` | ticket | TLS cert < 14 d to expiry (cert-manager metric) |

## Routing

A complete Alertmanager config ships at
[`ops/prometheus/alertmanager.yml`](../../ops/prometheus/alertmanager.yml) —
drop it in, or merge its `route` children and `inhibit_rules` into an existing
tree. What it does and why:

| Alert | Receiver | Cadence |
|---|---|---|
| `severity: page` | `proxilion-page` (on-call pager) | 15 s group wait, re-notify hourly |
| `alertname` = `ProxilionPcaVerifyFailure` or `ProxilionPicInvariantViolation` | `proxilion-security` | **no** group wait, re-notify every 30 m |
| `severity: ticket` (and anything unlabelled) | `proxilion-ticket` (team queue) | 30 s group wait, re-notify every 4 h |

Three decisions worth stating, because they are the difference between a
useful pager and an ignored one:

- **Grouping is by `alertname` + `slo`, never by instance.** A fleet-wide
  Trust Plane outage should page once, not once per replica.
- **The security invariants get their own receiver and skip the group wait.**
  A PCA verification failure or a PIC invariant violation is a possible
  compromise, not a capacity problem; it should not queue behind a noisier
  alert, and it should be visibly distinct in the pager timeline at incident
  review. The receiver is separate so it can route to security on-call rather
  than platform on-call.
- **Two inhibitions stop one fault paging three times.**
  `ProxilionTrustPlaneDown` suppresses the issuance/callback failures it
  causes, and a fast-burn page suppresses the slow-burn ticket for the same
  SLO.

Every alert's `runbook_url` is carried into the notification body, so a page
at 3am arrives with its procedure attached; they resolve into
[runbooks/](./runbooks/).

## Validation

Both halves are gated in CI
([prometheus-rules.yml](../../.github/workflows/prometheus-rules.yml)) on every
change to `ops/prometheus/`:

- `promtool check rules ops/prometheus/alerts.yml` + `check config`
- `amtool check-config ops/prometheus/alertmanager.yml`

The routing tree itself is checkable locally:

```bash
amtool config routes test --config.file=ops/prometheus/alertmanager.yml \
  'severity="page"' 'alertname="ProxilionPcaVerifyFailure"'
# → proxilion-security
```
