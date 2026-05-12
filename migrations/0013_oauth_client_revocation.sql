-- Soft-revocation for oauth_clients. ui-less-surfaces.md §4.1 — the
-- `proxilion-cli clients revoke <id>` subcommand sets this so the OAuth
-- authorize handler can refuse the client without us having to delete
-- the row (which would cascade-orphan historical oauth_sessions).

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_reason TEXT;

-- Partial index so the authorize-path lookup stays fast as the table
-- accumulates revoked rows.
CREATE INDEX IF NOT EXISTS oauth_clients_active
    ON oauth_clients (id)
    WHERE revoked_at IS NULL;
