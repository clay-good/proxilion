-- OAuth interception + PIC chain storage. Authority: spec.md §1.1.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE oauth_clients (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    redirect_uris   TEXT[] NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the one v1 client.
INSERT INTO oauth_clients (id, name, redirect_uris) VALUES
    ('anthropic-managed-claude',
     'Anthropic Managed Claude',
     ARRAY['https://claude.ai/oauth/callback']);

CREATE TABLE oauth_sessions (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                       TEXT NOT NULL REFERENCES oauth_clients(id),
    agent_redirect_uri              TEXT NOT NULL,
    agent_state                     TEXT NOT NULL,
    agent_code_challenge            TEXT NOT NULL,
    agent_code_challenge_method     TEXT NOT NULL CHECK (agent_code_challenge_method = 'S256'),
    agent_requested_scope           TEXT NOT NULL,
    pca_0_id                        UUID,
    p_0                             TEXT,
    granted_ops                     JSONB,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                      TIMESTAMPTZ NOT NULL
);
CREATE INDEX oauth_sessions_expires_at ON oauth_sessions (expires_at);

CREATE TABLE google_tokens (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id                  UUID NOT NULL REFERENCES oauth_sessions(id) ON DELETE CASCADE,
    access_token_ciphertext     BYTEA NOT NULL,
    access_token_nonce          BYTEA NOT NULL,
    refresh_token_ciphertext    BYTEA,
    refresh_token_nonce         BYTEA,
    scope                       TEXT NOT NULL,
    expires_at                  TIMESTAMPTZ NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pca_cache (
    pca_id          UUID PRIMARY KEY,
    cbor            BYTEA NOT NULL,
    p_0             TEXT NOT NULL,
    ops             JSONB NOT NULL,
    hop             INT NOT NULL,
    predecessor_id  UUID,
    signature       BYTEA NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX pca_cache_p_0 ON pca_cache (p_0);

CREATE TABLE agent_bearers (
    bearer_sha256       BYTEA PRIMARY KEY,
    session_id          UUID NOT NULL REFERENCES oauth_sessions(id) ON DELETE CASCADE,
    pca_1_id            UUID NOT NULL REFERENCES pca_cache(pca_id),
    google_tokens_id    UUID NOT NULL REFERENCES google_tokens(id) ON DELETE CASCADE,
    scope               TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT
);
CREATE INDEX agent_bearers_session ON agent_bearers (session_id);

CREATE TABLE auth_codes (
    code                            TEXT PRIMARY KEY,
    bearer_sha256_pending           BYTEA NOT NULL,
    session_id                      UUID NOT NULL REFERENCES oauth_sessions(id) ON DELETE CASCADE,
    code_challenge                  TEXT NOT NULL,
    code_challenge_method           TEXT NOT NULL,
    -- Bearer plaintext is briefly stored encrypted so the agent can fetch it
    -- on POST /oauth/google/token. Row is single-use (consumed_at set on
    -- exchange) and 30s TTL.
    bearer_ciphertext               BYTEA NOT NULL,
    bearer_nonce                    BYTEA NOT NULL,
    expires_at                      TIMESTAMPTZ NOT NULL,
    consumed_at                     TIMESTAMPTZ
);
CREATE INDEX auth_codes_expires_at ON auth_codes (expires_at);
