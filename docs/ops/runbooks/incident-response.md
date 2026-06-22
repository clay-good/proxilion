# Runbook — Security incident response & incident command

> The plan an on-call engineer follows when a paging alert (or a report)
> indicates a **security** event, not just an availability one. Reuses the
> severity matrix and coordinated-disclosure SLA from
> [SECURITY.md](../../../SECURITY.md). Index: [README.md](./README.md).

Proxilion's whole value is that authority cannot be forged. So the incidents
that matter most are **integrity** incidents — a forged chain, an auth bypass,
a tampered audit feed — where the right move is often to *preserve evidence and
fail closed*, not to restore throughput as fast as possible.

## Severity matrix (from SECURITY.md)

| Severity | Examples | Patch SLA |
|---|---|---|
| **Critical** | PCA chain forgery, federation/auth bypass, RCE, audit-log tampering | 7 days, coordinated disclosure |
| **High** | DoS of a deployed proxy, operator-scope bypass, secret exposure | per SECURITY.md |
| **Medium / Low** | lower-impact, batchable | 30 days |

Acknowledge external reports within **72 h**; triage within **7 days**
([SECURITY.md](../../../SECURITY.md)).

## Which alerts are security incidents (not just ops)

These page as integrity events — go straight to the IC checklist:

- `ProxilionPcaVerifyFailure` — a PCA failed signature verification. Must
  always read zero. ([README.md#pca-verification-failure](./README.md#pca-verification-failure))
- `ProxilionPicInvariantViolation` — a PIC chain invariant broke.
  ([README.md#pic-invariant-violation](./README.md#pic-invariant-violation))
- An **unexplained killswitch fire** (no matching operator action) → possible
  compromised operator token ([killswitch.md](./killswitch.md)).
- A confirmed **key leak** ([key-compromise.md](./key-compromise.md)).

## Incident-commander checklist

The IC owns coordination, not every fix. Work top to bottom; do not skip
**Preserve** to get to **Mitigate**.

1. **Declare.** State severity (table above), a one-line scope ("forged chain
   on session X"), and name the IC. Open an incident channel.
2. **Preserve evidence — before mitigating.** The audit log is
   **cryptographically verifiable** — it is your primary evidence; protect it
   first.
   - Snapshot the affected DB (the audit/`pca` rows, `kill_records`,
     `oauth_sessions`) to immutable storage **before** any cleanup,
     rollback, or cache flush.
   - Export the relevant action log (`proxilion-cli actions export …`) and the
     offending chain (`proxilion-cli pic show <id>` / `pic verify <id>`).
   - Capture replica logs and the current Grafana state.
   - Note exact timestamps — the chain and `kill_records.created_at` are
     authoritative.
3. **Contain (fail closed).** Stop authority from being exercised under the
   suspect condition:
   - Suspected forged/tampered chain → **killswitch** the affected scope
     (`session`/`user`/`all`, dry-run first) — [killswitch.md](./killswitch.md).
   - Suspected key leak → emergency rotation —
     [key-compromise.md](./key-compromise.md).
   - Suspected compromised operator token → revoke it
     (`proxilion-cli tokens …`) and rotate.
   - Never disable verification to "restore service." Fail-closed is the
     designed behavior; do not engineer around it.
4. **Diagnose root cause** using the preserved evidence. For a verify failure,
   determine: tampering vs. a CAT-key rotation that hasn't propagated
   ([README.md#pca-verification-failure](./README.md#pca-verification-failure)).
5. **Eradicate & recover.** Apply the specific runbook
   (key-compromise / killswitch / db-failover); restore service only once the
   suspect authority can no longer be exercised.
6. **Verify.** Re-run chain verification on a sample
   (`proxilion-cli pic verify`); confirm the offending condition no longer
   reproduces; confirm the relevant security metric reads zero again.
7. **Communicate.** Internal stakeholders throughout. If user data / upstream
   tokens were in scope, follow the coordinated-disclosure SLA in
   [SECURITY.md](../../../SECURITY.md).
8. **Post-incident review.** Blameless timeline, root cause, the gap that let
   it happen, and the tracked follow-ups. Correct the runbook that was used
   against what actually happened.

## Evidence-preservation note

Because the audit log is tamper-evident, an attacker who *altered* history
leaves a verification failure — so a `ProxilionPcaVerifyFailure` is both the
alert **and** the evidence. Do not "fix" it by flushing the PCA cache or
re-signing until the failing artifact is preserved; the failure is what proves
the tampering.

**Drill:** tabletop this checklist against a simulated chain-forgery report at
least once before the first design partner go-live (PR-12 interlinks the
external assessment).
