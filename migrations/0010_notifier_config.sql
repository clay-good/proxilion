-- Notifier configuration in DB (ui-less-surfaces.md §8.4).
--
-- Before this migration the proxy read PROXILION_BLOCKED_WEBHOOK_URL +
-- _HMAC_KEY from env only — operators had to restart to change them. This
-- table lets `proxilion-cli notifier set webhook ...` (and a future
-- /api/v1/notifier/config POST) update notifier config live with the
-- proxy hot-swapping its WebhookNotifier on the next request.
--
-- Bootstrap order (server.rs): DB row wins. Env-only is preserved as a
-- fallback for the no-postgres dev path.

CREATE TABLE IF NOT EXISTS notifier_config (
    -- One row per driver. v1 ships only 'webhook'; 'slack' / 'email'
    -- land when the §5.3 / §5.4 drivers do.
    id          TEXT PRIMARY KEY CHECK (id IN ('webhook','slack','email')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    config      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT
);
