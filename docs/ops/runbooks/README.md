# Proxilion runbooks

> One procedure per paging alert and per critical operation. Every alert in
> [`ops/prometheus/alerts.yml`](../../../ops/prometheus/alerts.yml) links here
> via its `runbook_url`. This is the **PR-5 first pass** — each entry has a
> real detection → diagnosis → mitigation → verification → escalation
> skeleton; **PR-6** expands them and drill-tests the killswitch and
> DB-failover procedures in staging.

General: check the Grafana dashboard ([ops/grafana/proxilion.json](../../../ops/grafana/proxilion.json))
and `GET /healthz` (per-dependency readiness) first. Severity matrix +
disclosure SLA: [SECURITY.md](../../../SECURITY.md).

## Availability error budget burn

- **Detect:** `ProxilionAvailabilityFastBurn`/`SlowBurn`. SLI =
  `upstream_errors / adapter_requests` (policy blocks are NOT errors).
- **Diagnose:** is it one vendor/action? `sum by (vendor,action)
  (rate(proxilion_adapter_upstream_errors_total[5m]))`. Check
  `ProxilionTrustPlaneDown` and upstream SaaS status.
- **Mitigate:** if upstream-SaaS-driven, it's largely external — confirm and
  communicate. If proxy-driven (deploy regression), roll back the proxy image.
- **Verify:** error ratio drops below the burn threshold; budget stops burning.
- **Escalate:** sustained fast-burn with no upstream cause → page the service owner.

## Added latency high

- **Detect:** `ProxilionPolicyEvalLatencyHigh` (p99 policy eval > 5 ms).
- **Diagnose:** correlate with a policy-bundle change
  (`proxilion_policy_reload_success_total`) or CPU saturation. A pathological
  match-expr is the usual cause.
- **Mitigate:** revert the offending policy bundle; scale CPU if saturated.
- **Verify:** `proxilion_policy_evaluation_duration_seconds{quantile="0.99"}` < 1 ms.

## Federation IdP JWKS outage

- **Detect:** `ProxilionFederationCallbackFailing` / `ProxilionFederationBridgeDown`.
- **Diagnose:** is the IdP's `jwks_uri` reachable + serving the current `kid`?
  Fail-closed is by design (PR-1) — users see auth failures, not bypass.
- **Mitigate:** if the IdP rotated keys, the JWKS resolver refreshes once on an
  unknown `kid` (throttled); if the IdP is down, wait/communicate — do **not**
  disable verification.
- **Verify:** callback success ratio recovers.

## Trust Plane unavailable

- **Detect:** `ProxilionTrustPlaneDown` / `ProxilionPcaIssueFailing`.
- **Diagnose:** `GET /healthz` Trust Plane check; network policy/mTLS between
  proxy ↔ Trust Plane (see [tls-mtls-matrix.md](../tls-mtls-matrix.md)).
- **Mitigate:** restore the Trust Plane; issuance/verification resume. PCA
  cache absorbs brief blips.
- **Verify:** `proxilion_trust_plane_up == 1`, issuance failure ratio drops.

## PCA verification failure

- **Detect:** `ProxilionPcaVerifyFailure` (must always read zero).
- **Diagnose:** a tampered PCA loaded from cache **or** a CAT-key rotation
  that hasn't propagated. Treat as a potential integrity incident.
- **Mitigate:** confirm the CAT public key matches the Trust Plane's active
  signing key; flush the PCA cache; if tampering is suspected, invoke the
  killswitch and preserve the (cryptographically verifiable) audit log.
- **Escalate:** security incident path (SECURITY.md).

## PIC invariant violation

- **Detect:** `ProxilionPicInvariantViolation`. A PIC chain invariant broke.
- **Diagnose/Escalate:** capture the offending chain from the audit log;
  treat as an authority-graph integrity incident; escalate to security.

## Edge overload

- **Detect:** `ProxilionEdgeLoadShedding` (sustained 429/503).
- **Diagnose:** real traffic vs. abuse? `sum by (reason)
  (rate(proxilion_ingress_rejections_total[5m]))`; check per-IP distribution.
- **Mitigate:** scale out replicas (HPA); if abuse, tighten
  `PROXILION_RATE_LIMIT_*` or block upstream. Limits: PR-2 / [config](../../../crates/proxy/src/config.rs).
- **Verify:** rejection rate returns to ~0.

## NATS SIEM forwarder backlog

- **Detect:** `ProxilionNatsPublishFailing` / `ProxilionSiemForwardFailing`.
- **Diagnose:** the action/audit **pull** surfaces (`/api/v1/blocked`, audit
  export) remain authoritative — streaming is best-effort. Check NATS/SIEM
  endpoint health.
- **Mitigate:** restore the sink; backlog drains. State the fail-open (stream)
  vs. fail-closed (persisted audit row is always written first) contract.
- **Verify:** failure counters stop increasing.

## DB failover connection exhaustion

- **Detect:** `ProxilionAuditPersistFailing` (page) — audit/action rows failing
  to persist.
- **Diagnose:** Postgres primary health, connection count vs. `max_connections`,
  failover state. The audit log's durability is the product's value.
- **Mitigate:** fail over / restore the primary; add PgBouncer if connection
  exhaustion (PR-7). Pre-deploy backups gate migrations (PR-8).
- **Verify:** persistence counters resume; sample `/api/v1/pca/{id}/verify`.
- **PR-6:** this drill is executed in staging.

## Policy reload failure

- **Detect:** `ProxilionPolicyReloadFailing`. The proxy keeps the last-good
  bundle, so enforcement continues.
- **Mitigate:** fix the bundle (YAML/match-expr), re-apply; confirm
  `proxilion_policy_reload_success_total` increments.

## Approval path wedge

- **Detect:** `ProxilionApprovalBacklogGrowing` (`overrides_pending > 50`).
- **Diagnose:** Slack `trigger_id` expiry or email single-use-token issues
  (see the resolved 17th/18th-audit wedge fixes). Check
  `proxilion_slack_post_failures_total` / `proxilion_email_send_failures_total`.
- **Mitigate:** restore the notifier channel; pending items are pullable via
  `/api/v1/blocked`. Resolve stuck items there directly if needed.

## Certificate expiry

- **Detect:** `ProxilionCertExpirySoon` (< 14 d, cert-manager metric).
- **Mitigate:** confirm cert-manager renewal (`Certificate`/`Order` status);
  for the dev path, regenerate via `dev-cert.sh`. TLS posture:
  [tls-mtls-matrix.md](../tls-mtls-matrix.md).
