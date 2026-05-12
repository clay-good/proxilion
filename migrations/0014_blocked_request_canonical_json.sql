-- spec.md §2.1 dev 3 — persist the canonical request body alongside the
-- blocked-action row so the approval surface (Slack `[Why?]`, email
-- landing page, `proxilion-cli blocked show <id>`) can show the
-- approver what the agent actually tried to do, without re-reading
-- `action_events` and dealing with `audit_body: hash` rows that may
-- have only stored a digest.
--
-- The value is a JSON object the adapter builds at block time:
--   { method, path, vendor, action,
--     path_params: {...},       -- optional
--     body: {...}                -- only fields the adapter exposed
--                                -- to the policy engine (spec §5.4
--                                -- default-deny: no surprise leak) }
--
-- Adapter-side truncation: writes are capped at 4 KB to keep the
-- approver surface readable and the row size bounded. The 4 KB cap is
-- enforced in `crates/proxy/src/blocked.rs::canonical_request_json` so
-- the schema doesn't carry a constraint (we'd rather log a truncation
-- count metric than reject the insert and lose the audit trail).
--
-- NULL is allowed for back-compat: pre-0014 rows have no
-- `request_canonical_json`; the API surfaces it as the JSON `null` and
-- the renderers fall through to the pre-existing path/method display.

ALTER TABLE blocked_actions
    ADD COLUMN IF NOT EXISTS request_canonical_json TEXT NULL;
