-- Notifier tokens — ui-less-surfaces.md §5.4 / §8.4.
--
-- One-time-use, time-limited tokens that authorize a SINGLE approve or
-- reject action against a specific `blocked_actions` row. Minted by an
-- operator (via `POST /api/v1/blocked/{id}/issue-link`) and embedded in
-- an email body or Slack message; consumed by `GET/POST
-- /api/v1/notifier/approve` (operator-token-less — the link IS the
-- credential, which is why it's single-use + signed by the token_id).

CREATE TABLE IF NOT EXISTS notifier_tokens (
    token_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blocked_id    UUID NOT NULL REFERENCES blocked_actions(id) ON DELETE CASCADE,
    action        TEXT NOT NULL,
    approver_hint TEXT,
    issued_by     TEXT,                       -- operator name from the issuing token
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (action IN ('approve','reject'))
);

CREATE INDEX IF NOT EXISTS notifier_tokens_unconsumed
    ON notifier_tokens (blocked_id)
    WHERE consumed_at IS NULL;
