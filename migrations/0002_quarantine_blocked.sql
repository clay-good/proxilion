-- Read-filter quarantine records + Layer-A blocked-action audit log.
-- Authority: spec.md §1.4 + §1.3 deviation note (blocked_actions).

CREATE TABLE quarantined_payloads (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL,
    session_id      UUID,
    policy_id       TEXT,
    pattern         TEXT NOT NULL,
    snippet         TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX quarantined_payloads_request ON quarantined_payloads (request_id);
CREATE INDEX quarantined_payloads_at      ON quarantined_payloads (at DESC);

CREATE TABLE blocked_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL,
    session_id      UUID,
    vendor          TEXT NOT NULL,
    action          TEXT NOT NULL,
    -- Why blocked: 'policy' (Layer B) or 'pic_invariant' (Layer A).
    layer           TEXT NOT NULL CHECK (layer IN ('policy', 'pic_invariant', 'read_filter')),
    policy_id       TEXT,
    detail          TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX blocked_actions_at      ON blocked_actions (at DESC);
CREATE INDEX blocked_actions_session ON blocked_actions (session_id);

CREATE TABLE pca_verification_results (
    leaf_pca_id     UUID PRIMARY KEY REFERENCES pca_cache(pca_id),
    intact          BOOLEAN NOT NULL,
    links_verified  INT NOT NULL,
    broken_at       UUID,
    reason          TEXT,
    p_0             TEXT,
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
