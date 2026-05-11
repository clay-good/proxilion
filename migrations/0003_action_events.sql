-- Action event history.
--
-- Every adapter call (allow / block / require_confirmation / rate_limit) lands
-- here so the live feed in the admin UI can scroll history and the operator
-- CLI can run point-in-time queries. The action stream's broadcast channel
-- is the live tail; this table is the durable record.

CREATE TABLE action_events (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id              UUID NOT NULL,
    session_id              UUID,
    p_0                     TEXT NOT NULL,
    leaf_pca_id             UUID,
    vendor                  TEXT NOT NULL,
    action                  TEXT NOT NULL,
    method                  TEXT NOT NULL,
    path                    TEXT NOT NULL,
    status                  INT NOT NULL,
    decision                TEXT NOT NULL,        -- allow | block | require_confirmation | rate_limit
    block_reason            TEXT,
    read_filter_triggered   BOOLEAN NOT NULL DEFAULT false,
    quarantined_count       INT NOT NULL DEFAULT 0,
    policy_id               TEXT,
    extra                   JSONB,
    at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX action_events_at        ON action_events (at DESC);
CREATE INDEX action_events_p_0       ON action_events (p_0, at DESC);
CREATE INDEX action_events_decision  ON action_events (decision, at DESC);
CREATE INDEX action_events_vendor    ON action_events (vendor, action, at DESC);
