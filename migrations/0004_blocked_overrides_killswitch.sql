-- Step 2.3: extend blocked_actions to support the approve/reject loop
-- (justified override → new attested PCA branch).
-- Step 3.2: kill_records audit trail.
-- Authority: spec.md §2.3, §3.2 + ui-less-surfaces.md §5, §8.3-8.4.

ALTER TABLE blocked_actions
    ADD COLUMN IF NOT EXISTS status              TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'overridden')),
    ADD COLUMN IF NOT EXISTS p_0                 TEXT,
    ADD COLUMN IF NOT EXISTS method              TEXT,
    ADD COLUMN IF NOT EXISTS path                TEXT,
    ADD COLUMN IF NOT EXISTS predecessor_pca_id  UUID,
    ADD COLUMN IF NOT EXISTS requested_ops       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    ADD COLUMN IF NOT EXISTS missing_ops         TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    ADD COLUMN IF NOT EXISTS override_pca_id     UUID,
    ADD COLUMN IF NOT EXISTS justification       TEXT,
    ADD COLUMN IF NOT EXISTS approver_subject    TEXT,
    ADD COLUMN IF NOT EXISTS reject_reason       TEXT,
    ADD COLUMN IF NOT EXISTS resolved_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 minutes';

CREATE INDEX IF NOT EXISTS blocked_actions_status_at ON blocked_actions (status, at DESC);
CREATE INDEX IF NOT EXISTS blocked_actions_p0       ON blocked_actions (p_0);

-- Killswitch audit trail. The killswitch endpoint itself mutates
-- agent_bearers.revoked_at (already on the table); this records *why*
-- and by whom, and supports kill-by-user / kill-all aggregate scopes
-- that don't map cleanly to a single bearer row.
CREATE TABLE IF NOT EXISTS kill_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope               TEXT NOT NULL CHECK (scope IN ('session', 'user', 'all')),
    target              TEXT NOT NULL,           -- session_id (uuid as text) | p_0 | '*'
    reason              TEXT NOT NULL,
    operator_subject    TEXT,                    -- who triggered it (operator token / Slack user)
    bearers_revoked     INT NOT NULL DEFAULT 0,
    at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kill_records_at ON kill_records (at DESC);
