-- Step 2.4: PIC invariant violations recorded for audit-mode policies.
--
-- Authority: spec.md §2.4. In `runtime-gate` mode an invariant violation
-- aborts the request and is recorded on `blocked_actions` (layer =
-- 'pic_invariant'). In `audit` mode the request is allowed to proceed
-- using the predecessor's PCA as the leaf (no PCA_2 minted, since the
-- Trust Plane refused). We still want a row per violation for the
-- forensic record, the SIEM forwarder (§3.3), and the operator surfaces
-- (`/api/v1/pic_violations`).
--
-- This table is intentionally append-only.

CREATE TABLE IF NOT EXISTS pic_violations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id          UUID NOT NULL,
    session_id          UUID NOT NULL,
    p_0                 TEXT,
    vendor              TEXT NOT NULL,
    action              TEXT NOT NULL,
    method              TEXT NOT NULL,
    path                TEXT NOT NULL,
    policy_id           TEXT,
    predecessor_pca_id  UUID,
    attempted_ops       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    missing_atoms       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- 'audit' = request proceeded; 'runtime_gate' = request blocked.
    pic_mode            TEXT NOT NULL CHECK (pic_mode IN ('audit', 'runtime_gate')),
    -- Raw upstream Trust Plane refusal body (often the full ops-not-subset
    -- explanation). Useful for the chain inspector.
    detail              TEXT,
    at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pic_violations_at ON pic_violations (at DESC);
CREATE INDEX IF NOT EXISTS pic_violations_session ON pic_violations (session_id);
CREATE INDEX IF NOT EXISTS pic_violations_p0 ON pic_violations (p_0);
