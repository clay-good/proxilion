# `proxilion.action_event.v1` — wire contract

**Status:** stable. Field additions are non-breaking; consumers MUST ignore unknown fields. Type changes or removals bump the schema string to `v2` and emit `v1` in parallel for at least one minor release. Per [ui-less-surfaces.md](../specs/ui-less-surfaces.md) §6.2.

This document is the customer-facing contract for the action_event JSON shape carried by:

- The SIEM forwarder ([crates/proxy/src/forwarder/siem.rs](../../crates/proxy/src/forwarder/siem.rs)) — `x-proxilion-schema: proxilion.action_event.v1` per-event, `proxilion.action_event_batch.v1` per-batch.
- `GET /api/v1/actions/stream` (SSE, `event: action`) and `GET /api/v1/actions/export?format=ndjson` (one document per line).
- `GET /api/v1/actions` paginated list and `GET /api/v1/actions/{id}` single record.

## Top-level fields

| Field                     | Type            | Required | Notes |
|---------------------------|-----------------|----------|-------|
| `request_id`              | UUID            | yes      | Per-request id. Joins with `quarantined_payloads.request_id`, `action_event_bodies.request_id`, `blocked_actions.request_id`, `pic_violations.request_id`. |
| `agent_session_id`        | UUID            | yes      | The Proxilion session minted at OAuth completion. |
| `p_0`                     | string          | yes      | The PIC primary principal — the human identity established at `PCA_0`. Email-shaped today; opaque in the contract. |
| `leaf_pca_id`             | UUID or null    | yes      | The leaf PCA in cache that authorized this action. `null` when no successor was minted (Layer-B block before Trust-Plane round-trip). |
| `vendor`                  | string          | yes      | `google` today. Lowercase, stable. |
| `action`                  | string          | yes      | Dotted action verb, e.g. `drive.files.get`, `gmail.users.messages.send`, `calendar.events.insert`. |
| `method`                  | string          | yes      | HTTP method (`GET`, `POST`, …). |
| `path`                    | string          | yes      | Upstream path (post-proxy rewrite), e.g. `/drive/v3/files/{id}`. |
| `status`                  | u16             | yes      | HTTP status returned to the agent. `0` only on internal pre-upstream errors. |
| `decision`                | string          | yes      | One of `allow`, `block`, `require_confirmation`, `rate_limit`, `observe_block`, `observe_require_confirmation`, `observe_rate_limit`. The `observe_*` variants mean the policy would have denied in `enforce` mode but the request proceeded. |
| `block_reason`            | string or null  | yes      | Free-text on deny paths; null on `allow`. Not stable across versions — for human reading, not for parsing. Use `policy_id` + `decision` for routing. |
| `read_filter_triggered`   | bool            | yes      | `true` when a read-filter pattern matched the response body (regardless of whether the filter blocked or quarantined). |
| `quarantined_count`       | u32             | yes      | Number of read-filter matches that were redacted. `0` when `read_filter_triggered=false`. |
| `at`                      | RFC 3339        | yes      | UTC instant the proxy persisted the event. |
| `policy_id`               | string or null  | yes      | The id of the matched Layer-B policy. `null` when no policy matched (defaults to allow). |
| `extra`                   | object          | no       | Adapter-specific payload. Omitted from JSON when empty. See "extra fields" below. Field set may grow; consumers must ignore unknown keys. |

`schema` is **not** part of the in-band payload — it's carried in transport metadata:

- SIEM webhook: `x-proxilion-schema: proxilion.action_event.v1`.
- SSE: the event name (`event: action`) plus the URL imply the schema.
- NDJSON export / list / stream: the URL implies the schema; consumers stamp it on ingest.

## `extra` fields

Adapter-specific. Default-deny per [spec.md](../specs/spec.md) §5.4 — adapters opt in to surfacing body fields. Known keys today:

| Key                    | Adapter | Type    | Meaning |
|------------------------|---------|---------|---------|
| `request_path_params`  | drive   | object  | Path parameters parsed out of the route (e.g. `{"id": "abc"}` for `/drive/v3/files/{id}`). |
| `to_domain`            | gmail   | string  | Domain portion of the first `To:` recipient on `gmail.users.messages.send`. |
| `to_domains`           | gmail   | array   | All distinct `To:` recipient domains. |
| `external_recipient`   | gmail   | bool    | `true` when any recipient is outside the customer domain. |
| `attendee_domains`     | cal     | array   | Distinct attendee domains for `calendar.events.insert` / `update`. |
| `external_attendee`    | cal     | bool    | `true` when any attendee is outside the customer domain. |
| `pic_audit_violation`  | all     | string  | Trust-Plane refusal detail captured when `pic_mode: audit` — the request proceeded but the would-be violation is recorded. Null otherwise. |

## CSV export columns

`GET /api/v1/actions/export?format=csv` emits the same top-level fields without `extra`. The header line is committed to the wire contract:

```
id,request_id,session_id,p_0,leaf_pca_id,vendor,action,method,path,status,decision,block_reason,read_filter_triggered,quarantined_count,policy_id,at
```

`id` is the `action_events.id` database primary key (UUID), distinct from `request_id`. New fields are appended at the end; column order on existing fields never changes within `v1`.

## Sibling schemas

- `proxilion.action_event_batch.v1` — SIEM batch envelope: `{ "schema": "...", "events": [<v1 action_event>, ...], "count": N, "batched_at": "<rfc3339>" }`. The batched events themselves are full v1 objects.
- `proxilion.blocked_action.v1` — outbound notifier payload (Slack / email / generic webhook). See [crates/proxy/src/notifier/mod.rs](../../crates/proxy/src/notifier/mod.rs).
- `proxilion.blocked_action_burst.v1` — burst-summary payload. See [crates/proxy/src/notifier/webhook.rs](../../crates/proxy/src/notifier/webhook.rs).

These are documented separately and do not share field-level guarantees with `action_event.v1`.

## Versioning policy

- **Non-breaking** (does not bump `v1`): adding a new top-level field; adding a new key to `extra`; adding a new `decision` enum value (consumers must treat unknown values as opaque); adding a new column at the end of the CSV header.
- **Breaking** (bumps to `v2`): renaming or removing a top-level field; changing the type of an existing field; changing the column order or removing a CSV column; changing the meaning of an existing `decision` value.

`v1` will continue to be emitted alongside `v2` for at least one minor release.

## Consuming the stream

- **SSE (`/api/v1/actions/stream`)**: long-lived connection, `event: action` per item, `data:` carries the JSON object. Use `Last-Event-ID` for resumption (set to the most recently observed `request_id`).
- **NDJSON export**: streamed from a postgres cursor; memory is O(1). Order is `at ASC`. No pagination cursor — use `since` + `until` for chunking.
- **CSV**: same ordering, header on the first line.
- **SIEM webhook**: per-event POSTs by default; batched POSTs when `PROXILION_SIEM_BATCH_SIZE > 1`. HMAC signed in `x-proxilion-signature: sha256=<hex>`. Retried on transport / 5xx; never on 4xx.

## Retention

Proxilion does not manage retention. The proxy retains `action_events` indefinitely by default; operators choose between:

- Tiering to a SIEM via the forwarder (push) or the export endpoint (pull) and then deleting locally.
- Running `proxilion-cli actions purge --older-than <window>` on a cron — the local equivalent.

See [ui-less-surfaces.md](../specs/ui-less-surfaces.md) §6.3.
