# Proxilion Error Codes

This is the canonical registry of operator-visible error codes returned by
the proxy. Codes are stable: once published, the wire string never changes.
New variants may be added; existing ones never get renamed. Defined in
[`crates/shared-types/src/error_code.rs`](../crates/shared-types/src/error_code.rs).

Every code is `snake_case`. Default HTTP status applies unless the adapter
overrides it (e.g. queues the request and returns 202).

| Code | Status | When it fires | Operator action |
|---|---:|---|---|
| `pic_invariant_violation` | 403 | The Trust Plane refused to issue a successor PCA because the requested ops were not a subset of the predecessor's. The agent attempted an action outside the user's authority. | Either widen the user's IdP-group → ops mapping in `config/ops-mapping.yaml`, or restrict the agent's request. PIC invariants are non-negotiable by design. |
| `policy_blocked` | 403 | A Layer-B YAML policy with `decision: block` matched. | Inspect the `policy_id` and `detail` fields. If the block is correct, no action. If incorrect, edit the matching policy, approve with `proxilion-cli blocked approve <id>`, or grant a one-time override via Slack / email. |
| `require_confirmation` | 428 | A Layer-B policy demands a human confirmation token. | The agent must surface a confirmation prompt and resubmit with `X-Proxilion-Confirmation: <token>`. |
| `rate_limited` | 429 | A Layer-B policy enforced `rate_limit { burst, per_seconds }`. | Back off and retry. Adjust `rate_limit` thresholds in policy YAML if too aggressive. |
| `read_filter_blocked` | 403 | A read-filter `quarantine_action: block_request` pattern matched in the upstream response body. | Operator should inspect the quarantined payload row to see which pattern matched. If a false positive, tune the pattern. |
| `upstream_unavailable` | 502 | A non-fatal failure calling the upstream SaaS (network, 5xx). Already retried per the adapter's backoff policy. | Check vendor status page and `/healthz`. Retry will eventually succeed if the vendor is healthy. |
| `upstream_too_large` | 502 | Upstream returned a body exceeding the 10 MB cap. | Narrow the agent's request (e.g. Drive `fields=`) or raise the cap if you have a real need — body inspection slows on large payloads. |
| `policy_engine_error` | 500 | YAML or ops-template parse error during evaluation. | Validate the policy file with `proxilion-cli policy validate` and inspect proxy logs for the structured cause. |
| `internal_error` | 500 | Database failure, unexpected panic-caught error, or any failure with no operator-actionable cause. | File an issue at <https://github.com/clay-good/proxilion/issues> with the request_id from the response header. |

## Compatibility

- The enum is `#[non_exhaustive]`. Downstream `match` statements must include
  a wildcard arm to be forward-compatible.
- `database_error` and `internal_error` intentionally share the same wire
  string (`internal_error`). The variant distinction matters internally for
  metrics labeling and log enrichment, but the wire contract collapses them
  — an operator shouldn't be expected to distinguish "DB failure" from
  "other internal failure" without reading logs.
- Tests in `crates/shared-types/src/error_code.rs::tests::wire_strings_are_stable`
  pin the full `(variant → string)` mapping. Renaming a variant string will
  break CI loudly. This is the intended behavior.

## Where the codes show up

1. **Adapter HTTP responses** — `body.code` in the JSON envelope on every
   4xx/5xx response from `/google/*`.
2. **Action stream** — every `ActionEvent` with `decision != "allow"` carries
   the matching code.
3. **Audit log** — `action_events.decision` records the code string.
4. **PolicyTrace** — each `LayerOutcome` with `passed == false` includes the
   code on its `error_code` field. See qiuth-patterns.md §3.
5. **Metrics** — labels on `proxilion_blocks_total{reason}` and
   `proxilion_observe_would_have_blocked_total{reason}` use the same strings.

## Adding a new code

1. Add a new variant to `ErrorCode` (never reorder existing variants).
2. Map it in `as_str()` and `default_status()`.
3. Add a row to `wire_strings_are_stable` test.
4. Add a row to this table.
5. Map it from your error type's `code()` method.
6. If it's an `Allow`-time outcome (e.g. `read_filter_blocked`), wire it
   through the adapter's `proxy_request` template.
