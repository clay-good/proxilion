# Backup, restore & disaster recovery

> production-readiness.md **PR-8**. Postgres is the system of record for
> sessions, cached PCAs, the blocked queue, operator tokens, and the audit
> log. A cryptographically verifiable audit history is worth nothing if it
> isn't durable.

**Targets.** RPO ≤ **5 minutes**, RTO ≤ **1 hour**. Those are the numbers the
schedule below is sized for; change the schedule if you change the targets.

## 1. What must be backed up (and what must not sit next to it)

| Data | Where | Backed up by |
|---|---|---|
| `oauth_sessions`, `agent_bearers`, `google_tokens`, `pca_cache`, `blocked_actions`, `action_events`, `operator_tokens`, `kill_records` | Postgres | base backup + WAL archive |
| Policy bundle | Helm ConfigMap / GitOps repo | your Git history, not this procedure |
| Secrets (token-encryption key, executor seed, HMAC keys, TLS material) | Kubernetes `Secret` / Vault / ESO | your secret store's own backup |

**Do not back up the token-encryption key into the same store as the database
dumps.** `google_tokens` holds AES-256-GCM ciphertext of upstream OAuth
access/refresh tokens; a backup plus the DEK is full impersonation of every
linked user. Keep them in separate trust domains with separate access control
so restoring a database never implies the ability to decrypt it. See
[key-inventory.md](../key-inventory.md).

## 2. Backup strategy

Continuous WAL archiving plus periodic base backups, giving **point-in-time
recovery**. pgBackRest is the recommended tool (compression, incremental,
retention policy, parallel restore); the same shape works with
`pg_basebackup` + `archive_command` if you already have that.

| Knob | Value for the targets above |
|---|---|
| `archive_mode` / `archive_timeout` | `on` / `60s` — bounds RPO at one minute of WAL even on an idle cluster |
| Base backup | full weekly, incremental daily |
| Retention | 14 days of PITR window, minimum |
| Restore target | a scratch namespace, never the live primary |

An RPO of 5 minutes is met with room to spare by a 60-second `archive_timeout`;
the slack is there because WAL shipping to object storage is the part that
fails quietly.

## 3. PITR restore procedure

1. **Stop writing.** Scale the proxy Deployment to zero
   (`kubectl scale deploy/<release>-proxy --replicas=0`). Agents get connection
   failures, which is correct — a proxy writing into a half-restored database
   is worse.
2. **Restore to a scratch instance**, not over the primary:
   `pgbackrest --stanza=proxilion --type=time --target="<timestamp>" restore`.
3. **Promote and verify the schema.** Start Postgres, confirm
   `SELECT count(*) FROM _sqlx_migrations` matches the migration count the
   deployed image expects. A restore to a timestamp *before* a migration is a
   schema rollback in disguise — see §5.
4. **Verify the audit chain** (below) against the restored database.
5. **Cut over** the `DATABASE_URL` and scale the proxy back up.
6. **Record** the wall-clock elapsed. That number is your real RTO.

## 4. Post-restore integrity verification

A restore that silently lost or corrupted `pca_cache` rows still starts, still
serves, and still looks healthy — the damage surfaces months later at an audit.
Check it explicitly:

```bash
proxilion-cli --url https://proxy.internal --token "$PROXILION_OPERATOR_TOKEN" \
  pic verify-sample --limit 500 --max-chains 50
```

It samples the most recent action events, verifies each **distinct** chain they
reference, prints one line per chain, and exits non-zero if any chain is broken
— or if the sample came back empty, since an empty sample is not evidence of
integrity. `--format json` for a drill script. Any `BROKEN` line means the
restore is not usable: go back to §3 with an earlier target timestamp.

Follow it with the killswitch spot-check from
[killswitch.md](./killswitch.md) — revocations are the other thing a
point-in-time rewind can undo.

## 5. Migration safety

Migrations are **forward-only** (`sqlx::migrate!` at boot, no down-migrations).
The rollback story is therefore the **expand/contract** pattern, not a schema
revert:

- **Expand** — additive migration (new nullable column, new table). Deploy it
  ahead of the code that uses it.
- **Migrate** — deploy the code. Both old and new images run against this
  schema, so a rollback of the *image* is safe.
- **Contract** — drop the old column in a later release, once no deployed
  image references it.

Never combine expand and contract in one release; that is what makes an image
rollback impossible. Take a base backup immediately **before** applying any
contract migration. Bad-migration recovery is in
[db-failover.md](./db-failover.md).

## 6. Drill log

*(placeholder — PR-8 acceptance)*

| Date | Target timestamp | RTO achieved | Chains verified | Notes |
|---|---|---|---|---|
| — | — | — | — | not yet executed against a staging stand-up |

The drill is: restore to an arbitrary timestamp in a scratch environment,
complete within RTO, pass §4 verification, and correct this runbook against
whatever it reveals.
