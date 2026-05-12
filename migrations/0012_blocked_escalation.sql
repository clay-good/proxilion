-- ui-less-surfaces.md §5.7 dev 2 — 10-min escalation to a backup channel.
--
-- When a blocked_action's `notifier_recipients.escalation_after_minutes`
-- is set in policy.yaml, the adapter computes
--   escalation_at = blocked_at + escalation_after_minutes
-- and writes it on the INSERT. The expiry sweeper picks up rows with
-- `escalation_at < now() AND escalated_at IS NULL AND status = 'pending'`
-- and re-fires the email notifier (subject prefixed REMINDER:), then
-- stamps `escalated_at = now()` so we don't escalate twice.
--
-- Rows without a configured escalation (legacy + opt-out) have
-- escalation_at NULL and are skipped by the sweeper.

ALTER TABLE blocked_actions
    ADD COLUMN IF NOT EXISTS escalation_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS escalated_at  TIMESTAMPTZ NULL;

-- Partial index — only the small set of pending-unescalated-due rows
-- gets indexed. Keeps the index narrow on a table that's small but
-- gets scanned every 60 seconds by the sweeper.
CREATE INDEX IF NOT EXISTS blocked_actions_escalation_due
    ON blocked_actions (escalation_at)
    WHERE status = 'pending'
      AND escalation_at IS NOT NULL
      AND escalated_at IS NULL;
