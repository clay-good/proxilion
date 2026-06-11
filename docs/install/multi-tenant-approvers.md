# Multi-tenant approver mapping — Slack → Proxilion operator identity

Closes [ui-less-surfaces.md §11 open question #4](../specs/ui-less-surfaces.md).

When a Slack approver clicks **Approve** or **Reject** on a Block Kit
message, the proxy needs to translate the Slack identity
(`payload.user.id` like `U01ABC23DEF`, or `payload.user.username`) into
the operator identity that attests the override PCA. That operator
identity is what lands on the audit row and on the override PCA's
`approver_subject` field, and downstream — what shows up under "who
overrode this?" in a quarterly review or an incident reconstruction.

Three deployment shapes, picked by team size.

---

## 1. Tier A — under ~25 approvers: the static `user_map`

The shipped path (`ui-less-surfaces.md §5.3` deviation 4). Configure
inline on the Slack notifier:

```bash
proxilion-cli notifier set-slack \
    --incoming-webhook-url "https://hooks.slack.com/services/T0…/B0…/…" \
    --signing-secret "…" \
    --user-map '{
      "U01ABCDEF":  "alice@acme.com",
      "U01ZZZ999":  "bob@acme.com",
      "carol":      "carol@acme.com"
    }'
```

Keys can be either a Slack user id (`U…`) or a username; id is
consulted first, username as a fallback. Values are the operator
identity Proxilion records — typically the operator's corporate email
so it correlates with the rest of the audit trail.

**When this works.** A small security team where the approver roster
is stable and edits are infrequent. Adding a new approver is a
single-line edit + `set-slack`; the change hot-applies.

**When it stops working.** When you find yourself rebuilding the map
from a directory export, or when an approver leaves the org and stays
in the map for a week.

---

## 2. Tier B — 25 to ~250 approvers: cron-sync the map from your IdP

Same `notifier_config.slack.user_map` shape, but rebuild the JSON from
your IdP on a schedule. Okta is the most common case; the pattern
generalizes.

**The flow:**

1. A small sync job runs on a cron (every 15 min is plenty — the map
   only matters when an approver clicks; staleness of minutes is fine).
2. The job queries Okta's SCIM API
   (`GET /api/v1/users?filter=profile.group eq "proxilion-approvers"`)
   and for each user pulls (a) the corporate email and (b) the linked
   Slack user id from the user's `profile.slackUserId` attribute (or
   whatever your Okta profile schema names it).
3. The job builds the `{slack_id: email}` JSON and POSTs it to
   `/api/v1/notifier/config` with an operator token holding
   `tokens:admin` scope.

**Skeleton (bash / `curl` / `jq`):**

```bash
#!/usr/bin/env bash
set -euo pipefail

OKTA_TOKEN="$(vault read -field=token secret/okta/scim)"
PROXILION_TOKEN="$(vault read -field=token secret/proxilion/sync-bot)"
PROXY_URL="https://proxilion.internal.acme.com"

USER_MAP="$(curl -fsS \
    -H "Authorization: SSWS ${OKTA_TOKEN}" \
    'https://acme.okta.com/api/v1/users?filter=profile.groupMembership%20co%20%22proxilion-approvers%22' \
  | jq 'map(select(.profile.slackUserId != null))
        | from_entries
        | map_values(.profile.email)
        | (reduce to_entries[] as $kv ({}; . + { ($kv.value.slackUserId): $kv.value.email }))')"

curl -fsS -X POST "${PROXY_URL}/api/v1/notifier/config" \
    -H "Authorization: Bearer ${PROXILION_TOKEN}" \
    -H 'content-type: application/json' \
    -d "$(jq -n --argjson m "$USER_MAP" \
              '{driver:"slack", config:{user_map:$m}}')"
```

The `set-slack` config merge is full-replace on `user_map`, so the
sync job is the source of truth — manual edits get clobbered on the
next tick. That's the point: removing someone from the Okta group
revokes their approval authority within one sync interval.

**Why not look up Slack-id → email on the fly during the interaction
webhook?** Slack gives the interaction webhook 3 seconds to respond.
A cross-region IdP call eats a chunk of that budget and adds a hard
dependency on the IdP being up at click time. A pre-computed map
keeps the hot path local-only.

---

## 3. Tier C — 250+ approvers: SCIM-pushed table, separate from `user_map`

At this size the JSON blob gets unwieldy (it's stored as a single
JSONB column on `notifier_config`) and you want SCIM **push** rather
than the proxy **pulling** on a cron. This is a v2 piece — Proxilion
v1 does not ship a SCIM endpoint. Two paths when you get there:

- **External SCIM proxy.** Stand up a tiny service that accepts SCIM
  from Okta / Azure AD and writes into a new `approver_directory`
  table the proxy joins against. The interaction webhook does the
  lookup in Postgres instead of in JSON. Latency is unchanged
  (single-digit ms either way); auditability goes up because the
  table has a history.

- **Native SCIM endpoint in Proxilion.** Add `/scim/v2/Users` +
  `/scim/v2/Groups` behind operator-token auth. Same back-end
  storage. More code in the proxy; one fewer service to run.

Neither path is implemented in v1; both are sized at roughly a week
of engineering. If you're at this scale today, talk to us — the v2
shape is partly a function of which IdP you're standardizing on.

---

## 4. Audit + observability

Regardless of tier:

- `audit_log.approver_subject` records the resolved operator
  identity. An unmapped Slack click falls through to
  `slack:<username>` — easy to grep for in audit reviews to find
  "approvers who weren't in the directory."
- `proxilion_slack_interact_total{result="why"}` going up is the
  canary for "approvers are clicking *Why?* because they don't
  recognize the context." It often precedes a request to grow the
  map.
- `proxilion_slack_interact_total{result="rejected_signature"}` going
  up while the user_map is being rebuilt usually means the sync job
  is targeting the wrong tenant — Slack's signing secret is per
  workspace, not per directory.

## 4b. Capturing the approver's *justification* (optional bot token)

By default a Slack approve/reject records *who* but synthesizes the
*why* (`"approved via Slack by <user>"`). To capture the reviewer's
real justification, set a Slack **bot** token so the proxy can open a
Block Kit modal (surface-delight-and-correctness.md §4.1):

```bash
# A bot token (xoxb-…) for a Slack app with the `views:write` scope,
# installed to the workspace. Set in the proxy's environment.
export PROXILION_SLACK_BOT_TOKEN="xoxb-…"
```

With it set, an **Approve** click opens a modal with a required
free-text justification (≥ 20 chars, matching the email form); the
override commits only on submit, with the entered text written to the
audit row's `justification`. **Reject** opens the same modal with an
optional reason. The interaction endpoint already verifies Slack's
signed request, so the modal needs no extra auth wiring.

**Graceful by default.** With no `PROXILION_SLACK_BOT_TOKEN`, the
click commits immediately with the synthesized justification — exactly
as before. The token only *adds* the modal step; nothing else changes.
(`PROXILION_SLACK_API_BASE` overrides the Slack Web API base, used by
tests.)

## 5. What this doesn't do

- No support for **multi-Slack-workspace** Proxilion deployments in
  v1 — one `notifier_config.slack.signing_secret` per proxy. If your
  Slack-tenant story is multi-workspace, you'll need one Proxilion
  per workspace until that lands (`§11` open question #2).
- No support for **per-policy approver subsets** in the map. The
  map is workspace-wide; a policy that should be approved only by
  finance is enforced via `policy.yaml` `approvers:` (see
  `ui-less-surfaces.md §5.7`), not via slicing the map.
