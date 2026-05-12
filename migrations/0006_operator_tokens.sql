-- Operator tokens — ui-less-surfaces.md §4.4.
--
-- Tokens are `pxl_operator_<52 base32 chars>`. Only the SHA-256 hash is
-- persisted; the plaintext is shown to the operator exactly once at issue
-- time. Scopes are a curated string set; see crates/proxy/src/operator_auth.rs
-- for the catalogue.

CREATE TABLE IF NOT EXISTS operator_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 of the bearer (raw bytes). Lookups: WHERE token_hash = $1.
    token_hash    BYTEA NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    scopes        TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX IF NOT EXISTS operator_tokens_revoked
    ON operator_tokens (revoked_at)
    WHERE revoked_at IS NOT NULL;
