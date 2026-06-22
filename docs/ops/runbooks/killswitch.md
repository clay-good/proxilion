# Runbook — Killswitch operation & recovery

> Critical procedure (not alert-driven). Covers a **deliberate** revocation,
> the **propagation guarantee** across replicas, the **staging drill** that
> proves it, and **recovery from an accidental fleet-wide kill**.
> Index: [README.md](./README.md). Severity matrix / disclosure SLA:
> [SECURITY.md](../../../SECURITY.md).

The killswitch is Proxilion's emergency stop: it revokes an agent's right to
take any further action. Three scopes, each an operator-authenticated `POST`
(scope `killswitch:revoke`) or the equivalent CLI subcommand:

| Scope | Route | CLI | Blast radius |
|---|---|---|---|
| Session | `POST /api/v1/killswitch/session/{id}` | `proxilion-cli killswitch session <session-uuid>` | one OAuth session's bearer chain |
| User | `POST /api/v1/killswitch/user/{p0}` | `proxilion-cli killswitch user user:alice@org.com` | every active session for one `p_0` |
| All | `POST /api/v1/killswitch/all` (body `{"confirm":"yes"}`) | `proxilion-cli killswitch all --confirm yes` | every active session, fleet-wide |

Every form writes a `kill_records` row, flips `agent_bearers.revoked_at` for
the matching rows (`RETURNING bearer_sha256`), and seeds those hashes into the
in-process [kill-cache](../../../crates/proxy/src/kill_cache.rs). Postgres is
the source of truth; the cache is an `O(1)` short-circuit, not the authority.

## How propagation works (the M3 guarantee)

`spec.md` M3 requires a revocation to take effect within **one request cycle**.
The mechanism:

1. The killswitch handler commits the `agent_bearers.revoked_at` UPDATE
   **before** it returns. After commit, the row is revoked for *every* reader.
2. The bearer-auth middleware checks the kill-cache first. **Cache miss always
   falls through to the DB JOIN** — so a kill issued on replica A is enforced
   by replica B on B's very next request for that bearer, because B's cache has
   no entry and the DB now reports `revoked_at IS NOT NULL`. The per-process
   cache is a latency optimization for the *issuing* replica; it is never the
   thing that makes the kill correct.
3. Therefore the cross-replica propagation bound is **one DB-visible request
   cycle** — bounded by transaction commit, not by any cache TTL or pub/sub
   fan-out. (Shared/Redis-backed kill-cache is a v2 perf item, not a
   correctness gap — see [README.md#edge-overload](./README.md) and the PR-7
   statelessness audit.)

## Verify a deliberate kill took effect

- Response body: `bearers_revoked` > 0 (or the expected count); non-nil
  `record_id`.
- A replay of the agent's last request now returns `401 unauthorized`.
- `proxilion_kill_cache_marks_total` increments on the issuing replica.
- The `kill_records` row is queryable: `proxilion-cli` (or `psql`) shows the
  scope, target, reason, and `created_at`.

## Dry-run first (no TOCTOU)

Every scope accepts `--dry-run`: it counts the bearers that *would* be revoked
against the **same predicate** the real revoke uses, writes nothing (no UPDATE,
no `kill_records`, no cache write), and returns `record_id: nil`,
`dry_run: true`. Always dry-run a `user`/`all` kill to confirm the blast radius
before firing.

```sh
proxilion-cli killswitch all --dry-run        # how many sessions would die?
proxilion-cli killswitch all --confirm yes    # then fire
```

## Staging drill (PR-6 acceptance)

Run quarterly and after any change to the auth middleware or kill-cache. Two
replicas, sustained synthetic load against a known session.

1. Start ≥ 2 proxy replicas behind the LB; drive steady traffic for a known
   `pxl_live_*` bearer (the [stress scripts](../../../scripts/) work).
2. Issue `proxilion-cli killswitch session <id>` against **replica A** only
   (target A's pod directly to prove cross-replica enforcement).
3. Assert: the first request that lands on **replica B** *after* the UPDATE
   commits returns `401`. Capture the wall-clock delta between the kill
   response and B's first `401` — it must be ≤ one request cycle.
4. Assert: zero successful actions for that bearer after the kill timestamp
   (cross-check the action log / `kill_records.created_at`).
5. Record the measured propagation delta in the drill log below and correct
   this runbook against reality if the mechanism differs.

**Drill log:** _not yet executed in staging — schedule with the first
multi-replica staging stand-up (PR-7)._

## Recovery from an accidental kill

A killswitch is **soft and reversible at the DB layer** — the rows are marked,
not deleted — but the proxy has no "un-revoke" route by design (un-revoking is
a privileged, audited, deliberate act, not a one-keystroke undo). To recover:

1. **Stop the bleeding.** Confirm the scope from the `kill_records` row
   (`record_id`, `target`, `reason`). If `all` was fired by mistake, the
   `confirm: "yes"` guard means it was deliberate input — treat as a real
   incident and open the [IC checklist](./incident-response.md).
2. **Decide the policy.** The cleanest, audit-honest recovery is to have the
   affected users **re-authenticate** — a fresh OAuth flow mints a new session
   and new bearers, leaving the revoked rows as a truthful historical record.
   Prefer this for a `user`/`all` kill.
3. **If re-auth is not acceptable** (e.g. an `all` kill during peak), an
   operator may clear `revoked_at` for the specific rows **with a written
   change record**, then evict the kill-cache by rolling the affected replicas
   (the cache has no clear-route; a 1 h TTL or a pod restart drops it):

   ```sql
   -- scoped, reviewed, logged — never a blanket UPDATE
   UPDATE agent_bearers
      SET revoked_at = NULL, revoked_reason = NULL
    WHERE session_id = $1 AND revoked_reason = 'operator-initiated'
      AND revoked_at > $kill_timestamp;
   ```

   Then `kubectl rollout restart` the proxy deployment so no replica serves a
   stale kill-cache `401`. Verify a previously-killed bearer succeeds again.
4. **Always** annotate the original `kill_records` row's incident in the
   change log; the audit chain must explain both the kill and the reversal.

## Escalation

Accidental `all` kill, or any kill you cannot explain (no matching operator
action) → security incident path ([incident-response.md](./incident-response.md)),
because an unexplained killswitch fire can mean a compromised operator token.
