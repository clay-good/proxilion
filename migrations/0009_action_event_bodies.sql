-- Audit body retention (ui-less-surfaces.md §6.4).
--
-- Privacy default: bodies are NOT persisted. A policy may opt in via
-- `then.audit_body: hash | redact_pii | full`.
--
--   * hash       → store SHA-256 of request + response bytes (default for
--                  any policy that sets `audit_body` without further config)
--   * redact_pii → run a regex-based PII pass and persist the redacted text
--   * full       → persist raw bytes (use sparingly; respects customer's
--                  data-classification posture entirely)
--
-- We use a separate table from `action_events` so the hot path stays lean
-- — most rows will not have a corresponding `action_event_bodies` row.

CREATE TABLE IF NOT EXISTS action_event_bodies (
    -- Joined by request_id rather than action_events.id so the insert
    -- doesn't need to await the action_events FK target.
    request_id        UUID PRIMARY KEY,
    mode              TEXT NOT NULL CHECK (mode IN ('hash','redact_pii','full')),
    request_hash      TEXT,
    response_hash     TEXT,
    -- base64-encoded body bytes when mode is redact_pii or full.
    request_body_b64  TEXT,
    response_body_b64 TEXT,
    request_bytes     INT NOT NULL DEFAULT 0,
    response_bytes    INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS action_event_bodies_created_at
    ON action_event_bodies (created_at DESC);
