# Runbook — Postgres failover, connection exhaustion & bad migration

> Critical procedure. Postgres is the system of record for sessions, PCAs,
> the blocked queue, operator tokens, and the **cryptographically verifiable
> audit log** — its durability *is* the product's value. Paging alert:
> `ProxilionAuditPersistFailing`
> ([README.md#db-failover-connection-exhaustion](./README.md#db-failover-connection-exhaustion)).
> Interlinks PR-7 (HA) and PR-8 (backup/restore).

## Failure-mode triage

| Symptom | Likely cause | Jump to |
|---|---|---|
| `ProxilionAuditPersistFailing` firing; action/audit rows failing to insert | primary down, or pool exhausted | §1 / §2 |
| Latency spike + `pool timed out` in logs, primary healthy | connection exhaustion | §2 |
| New deploy boots then crashes / 500s right after rollout | incompatible migration | §3 |

First, always: Grafana DB row + `GET /healthz` (per-dependency readiness —
the `db` check reports reachability) + `kubectl logs` for `sqlx` pool errors.

## §1 — Primary failover

The proxy holds a connection pool to a single primary DSN (`DATABASE_URL`).
It does not orchestrate failover; the datastore tier (managed HA Postgres,
Patroni, or a cloud provider) owns the promotion.

1. **Confirm the primary is actually down** (not a network partition from one
   replica): check the datastore's own health/console, not just the proxy.
2. **Promote / fail over** per the datastore's procedure. If `DATABASE_URL`
   points at a VIP / service name that follows the new primary, the proxy
   reconnects automatically as the pool re-establishes; if it points at a
   pinned host, update the secret and `kubectl rollout restart`.
3. **Audit-stream behavior during the outage is fail-closed for persistence:**
   the persisted audit/action row is written **first**; NATS/SIEM streaming is
   best-effort on top (see
   [README.md#nats-siem-forwarder-backlog](./README.md#nats-siem-forwarder-backlog)).
   While the primary is unreachable, mutating actions that cannot persist their
   audit row fail rather than proceed unlogged — this is intended: no action
   without a durable record.
4. **Verify:** `ProxilionAuditPersistFailing` clears; `/healthz` `db` is ready;
   sample-verify a fresh chain end-to-end: `proxilion-cli pic verify <leaf-id>`
   returns `intact:true`.

## §2 — Connection exhaustion

The pool size × replica count must stay under Postgres `max_connections`.

1. **Quantify:** `SELECT count(*) FROM pg_stat_activity;` vs `SHOW
   max_connections;`. Identify whether it's Proxilion (many idle-in-pool) or a
   neighbor on the same instance.
2. **Mitigate now:** scale the proxy *down* if replica × pool overshot
   `max_connections` (counter-intuitively, more replicas can make it worse), or
   terminate leaked sessions. Longer-term, front Postgres with **PgBouncer**
   (transaction pooling) so replica count decouples from backend connections —
   this is the PR-7 capacity-model decision.
3. **Verify:** `pg_stat_activity` count falls below `max_connections` with
   headroom; pool-timeout log lines stop.

## §3 — Migration gone wrong

Migrations (`migrations/0001`–`00NN`) are applied by `sqlx::migrate!` at boot
and are **forward-only**. A migration incompatible with the running binary
wedges the deploy.

1. **Do not** hand-edit `_sqlx_migrations`. Roll the **binary** back to the
   prior image (the schema is designed expand/contract — the old binary
   tolerates the new column).
2. If the migration itself is destructive/incompatible (contract phase ran too
   early), restore from the **pre-deploy backup** (PR-8) to the point just
   before the migration and re-apply forward with the fix. This is why
   PR-8 gates every deploy on a fresh base backup.
3. **Policy:** ship schema changes expand-first (add nullable column / new
   table → deploy code that writes both → backfill → contract in a *later*
   release). Never combine an add and a drop of the same object in one deploy.

## Staging drill (PR-6 / PR-8 acceptance)

1. Stand up HA Postgres + ≥ 2 proxy replicas under steady load.
2. Kill the primary; time the datastore promotion and the proxy's recovery to
   first-successful-write.
3. Assert no audit row was *silently* lost: every action that returned success
   has a persisted row; every action that could not persist returned an error
   to the agent (fail-closed).
4. Run a **PITR restore** to a timestamp mid-load into a scratch DB and verify
   audit-chain integrity (`/api/v1/pca/{id}/verify` sampling) on the restored
   copy.
5. Record RPO (data lost) and RTO (time to first write) against the PR-8
   targets; correct this runbook.

**Drill log:** _not yet executed — schedule with the PR-7/PR-8 staging
stand-up._

## Escalation

Suspected data loss or audit-chain break post-restore → security incident path
([incident-response.md](./incident-response.md)); the audit log's integrity is
a security property, not just an availability one.
