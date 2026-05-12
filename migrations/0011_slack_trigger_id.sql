-- ui-less-surfaces.md §5.3 — Slack interaction idempotency.
--
-- When Slack retries an interaction webhook (timeout, network blip, or
-- the user rapidly double-clicks Approve), each delivery carries the
-- same `trigger_id` at the top of the payload. Recording the trigger_id
-- on `blocked_actions` lets the Slack interact handler return an
-- idempotent success on retry instead of double-minting an override PCA
-- (which the FOR UPDATE inside `approve_inner` already prevents) or
-- worse, returning 409 to a Slack user who only meant to click once.

ALTER TABLE blocked_actions
    ADD COLUMN IF NOT EXISTS slack_trigger_id TEXT;

-- Unique only when set — keeps existing rows valid and rejects two
-- distinct trigger_ids attempting to claim the same blocked row.
CREATE UNIQUE INDEX IF NOT EXISTS blocked_actions_slack_trigger_id_uniq
    ON blocked_actions (slack_trigger_id)
    WHERE slack_trigger_id IS NOT NULL;
