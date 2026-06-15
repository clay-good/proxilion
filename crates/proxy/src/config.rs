//! Proxy configuration loaded from environment and/or a TOML file.
//!
//! ## Loading
//!
//! Production: [`Config::load`] — defaults → optional TOML file
//! (`PROXILION_CONFIG_FILE`) → env vars. Programmatic / embed:
//! [`ConfigBuilder`].
//!
//! ## Layering
//!
//! ```text
//! defaults  →  optional TOML file  →  env vars  →  programmatic overrides
//! ```
//!
//! - Phase 1 (shipped 2026-05-12): `ConfigBuilder` exists, `Config::from_env`
//!   is a thin wrapper around it.
//! - Phase 2 (shipped 2026-05-12): `ConfigBuilder::from_file` (TOML),
//!   `Config::load` honors `PROXILION_CONFIG_FILE` underneath env.
//! - Phase 3 (shipped 2026-05-13): `Config::from_env` removed — callers are
//!   migrated to `Config::load` (production) or `ConfigBuilder` (embed/test).

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Render a capability URL down to a non-secret `scheme://host[:port]` label
/// for logging.
///
/// Several operator-supplied endpoints embed secrets *in the URL itself*:
/// a Slack incoming-webhook URL carries its token in the path
/// (`hooks.slack.com/services/T…/B…/XXXX`), a generic webhook or SIEM URL may
/// carry auth in the path/query, and a NATS URL may carry `user:pass@` userinfo.
/// Logging the raw URL (`url = %url`, or a `reqwest::Error` whose `Display`
/// appends ` for url (…)`) leaks those secrets into log aggregation/SIEM. This
/// strips everything but scheme + host + port. Unparseable input collapses to a
/// fixed placeholder rather than echoing the raw string.
pub(crate) fn redacted_endpoint(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => match u.host_str() {
            Some(host) => match u.port() {
                Some(port) => format!("{}://{}:{}", u.scheme(), host, port),
                None => format!("{}://{}", u.scheme(), host),
            },
            None => format!("{}://(no host)", u.scheme()),
        },
        Err(_) => "(unparseable url)".to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    // Wired in later steps (sqlx pool, log-format selection moves out of main.rs).
    pub database_url: Option<String>,
    pub trust_plane_url: String,
    pub federation_bridge_url: String,
    pub log_format: LogFormat,
    /// Hex-encoded 32-byte key for AES-256-GCM token encryption.
    pub token_encryption_key_hex: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    /// Proxy's own public base URL (handed to upstream OAuth as redirect_uri).
    pub proxy_base_url: String,
    /// Path to a YAML file with Layer-B policy docs. If unset, the adapter
    /// engine evaluates with an empty policy set (everything defaults Allow).
    pub policy_path: Option<PathBuf>,
    /// Customer's primary domain, used for `${customer_domain}` substitution.
    pub customer_domain: String,
    /// If true, generate a self-signed cert at `tls_cert_path` / `tls_key_path`
    /// when they don't exist. Set via `PROXILION_DEV=1`.
    pub dev_mode: bool,
    /// Optional NATS server URL (e.g. `nats://nats:4222`). When set, every
    /// persisted action event is also published to NATS on subject
    /// `<prefix>.<vendor>.<action>`. Spec.md §3.1.
    pub nats_url: Option<String>,
    /// NATS subject prefix (default "actions").
    pub nats_subject_prefix: String,
    /// Optional SIEM webhook URL. When set, every persisted action event is
    /// POSTed to this URL with an HMAC-signed body. Spec.md §3.3.
    pub siem_webhook_url: Option<String>,
    /// Hex-encoded HMAC secret for `X-Proxilion-Signature`. Required when
    /// `siem_webhook_url` is set.
    pub siem_hmac_key_hex: Option<String>,
    /// Optional SIEM batch size — spec.md §3.3 dev 2. When `Some(n>1)`,
    /// the forwarder collects up to `n` events into a single POST. When
    /// `None` or `Some(1)`, per-event delivery (the original behavior).
    /// Customers running low-volume keep the default; high-volume Splunk
    /// HEC / Elastic clusters set this to amortize TLS overhead.
    pub siem_batch_size: Option<usize>,
    /// Maximum delay before a partially-filled batch is flushed.
    /// Defaults to 5 seconds when `siem_batch_size > 1`.
    pub siem_batch_max_age_secs: u64,
    /// Optional blocked-action webhook URL (ui-less-surfaces.md §10.3). When
    /// set, every persisted `blocked_actions` row fires a signed POST.
    pub blocked_webhook_url: Option<String>,
    /// Hex-encoded HMAC key for the blocked-action webhook.
    pub blocked_webhook_hmac_key_hex: Option<String>,
    /// When true (default), `/api/v1/*` requires a valid `pxl_operator_*`
    /// bearer. Set `PROXILION_DISABLE_OPERATOR_AUTH=1` to bypass for local
    /// dev. ui-less-surfaces.md §4.4.
    pub operator_auth_enforced: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid bind addr {0:?}: {1}")]
    BindAddr(String, std::net::AddrParseError),
    #[error("TLS cert not found at {0}")]
    MissingCert(PathBuf),
    #[error("TLS key not found at {0}")]
    MissingKey(PathBuf),
    #[error("invalid value for {field}: {reason}")]
    InvalidValue { field: &'static str, reason: String },
    #[error("config file {path}: {reason}")]
    FileLoad { path: PathBuf, reason: String },
}

impl Config {
    /// Production entry point: defaults → optional TOML file (when
    /// `PROXILION_CONFIG_FILE` is set) → env vars. Validates via
    /// [`ConfigBuilder::build`].
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder = ConfigBuilder::defaults();
        if let Ok(path) = env::var("PROXILION_CONFIG_FILE") {
            if !path.is_empty() {
                builder = builder.from_file(&path)?;
            }
        }
        builder.from_env_layer()?.build()
    }
}

// =====================================================================
// ConfigBuilder — qiuth-patterns.md §2
// =====================================================================

/// Fluent builder for [`Config`]. Validation runs in [`Self::build`] so
/// callers get a single point to catch malformed inputs (token-encryption
/// key length, URL shape, dev-mode-vs-cert).
///
/// Designed for two usage modes:
///
/// 1. **Production:** `Config::load()` — wraps
///    `ConfigBuilder::defaults().from_file(?)?.from_env_layer()?.build()`.
/// 2. **Embed / test:** `ConfigBuilder::defaults().with_bind_addr(...).with_trust_plane_url(...).build()`.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    bind_addr: SocketAddr,
    tls_cert_path: PathBuf,
    tls_key_path: PathBuf,
    database_url: Option<String>,
    trust_plane_url: String,
    federation_bridge_url: String,
    log_format: LogFormat,
    token_encryption_key_hex: Option<String>,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
    proxy_base_url: String,
    policy_path: Option<PathBuf>,
    customer_domain: String,
    dev_mode: bool,
    nats_url: Option<String>,
    nats_subject_prefix: String,
    siem_webhook_url: Option<String>,
    siem_hmac_key_hex: Option<String>,
    siem_batch_size: Option<usize>,
    siem_batch_max_age_secs: u64,
    blocked_webhook_url: Option<String>,
    blocked_webhook_hmac_key_hex: Option<String>,
    operator_auth_enforced: bool,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::defaults()
    }
}

impl ConfigBuilder {
    /// Built-in defaults — equivalent to the prior env-only fallbacks.
    pub fn defaults() -> Self {
        Self {
            bind_addr: "0.0.0.0:8443"
                .parse()
                .expect("compile-time default bind addr"),
            tls_cert_path: PathBuf::from("./certs/dev.crt"),
            tls_key_path: PathBuf::from("./certs/dev.key"),
            database_url: None,
            trust_plane_url: "http://trust-plane:8080".to_string(),
            federation_bridge_url: "http://federation-bridge:8081".to_string(),
            log_format: LogFormat::Json,
            token_encryption_key_hex: None,
            google_client_id: None,
            google_client_secret: None,
            proxy_base_url: "https://localhost:8443".to_string(),
            policy_path: None,
            customer_domain: "example.com".to_string(),
            dev_mode: false,
            nats_url: None,
            nats_subject_prefix: "actions".to_string(),
            siem_webhook_url: None,
            siem_hmac_key_hex: None,
            siem_batch_size: None,
            siem_batch_max_age_secs: 5,
            blocked_webhook_url: None,
            blocked_webhook_hmac_key_hex: None,
            operator_auth_enforced: true,
        }
    }

    /// Layer environment variables on top of the current values. Empty
    /// strings on optional vars are filtered like the prior loader did.
    ///
    /// **Naming note:** `from_*` taking `self` violates clippy's
    /// `wrong_self_convention`, which expects constructors. This is a
    /// fluent-builder *layer* method (qiuth-patterns.md §2 — the same
    /// shape as `ConfigBuilder::from_file`); the `from_` prefix
    /// describes the *source* being layered in, not a constructor.
    /// Renaming to `with_env_layer` would be more conventional but
    /// would break the published API surface; suppression with
    /// rationale is the right trade.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_env_layer(mut self) -> Result<Self, ConfigError> {
        if let Ok(raw) = env::var("PROXILION_BIND_ADDR") {
            self.bind_addr = raw
                .parse()
                .map_err(|e| ConfigError::BindAddr(raw.clone(), e))?;
        }
        if let Ok(v) = env::var("PROXILION_TLS_CERT") {
            self.tls_cert_path = PathBuf::from(v);
        }
        if let Ok(v) = env::var("PROXILION_TLS_KEY") {
            self.tls_key_path = PathBuf::from(v);
        }
        if matches!(env::var("PROXILION_DEV").as_deref(), Ok("1") | Ok("true")) {
            self.dev_mode = true;
        }
        if let Ok(v) = env::var("PROXILION_LOG_FORMAT") {
            self.log_format = if v.eq_ignore_ascii_case("pretty") {
                LogFormat::Pretty
            } else {
                LogFormat::Json
            };
        }
        if let Ok(v) = env::var("DATABASE_URL") {
            self.database_url = Some(v);
        }
        if let Ok(v) = env::var("PROXILION_TRUST_PLANE_URL") {
            self.trust_plane_url = v;
        }
        if let Ok(v) = env::var("PROXILION_FEDERATION_BRIDGE_URL") {
            self.federation_bridge_url = v;
        }
        if let Ok(v) = env::var("PROXILION_TOKEN_ENCRYPTION_KEY") {
            self.token_encryption_key_hex = Some(v);
        }
        if let Ok(v) = env::var("GOOGLE_CLIENT_ID") {
            self.google_client_id = Some(v);
        }
        if let Ok(v) = env::var("GOOGLE_CLIENT_SECRET") {
            self.google_client_secret = Some(v);
        }
        if let Ok(v) = env::var("PROXILION_PUBLIC_URL") {
            self.proxy_base_url = v;
        }
        if let Ok(v) = env::var("PROXILION_POLICY_PATH") {
            self.policy_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = env::var("PROXILION_CUSTOMER_DOMAIN") {
            self.customer_domain = v;
        }
        // These five are `Option`/`Some`-valued *and* settable from the TOML file,
        // which is layered in BEFORE this env layer (see `Config::load`). They MUST
        // use the same `if let Ok` guard as every other field: an unconditional
        // `self.x = env::var(..).ok()...` evaluates to `None` when the var is unset
        // and silently clobbers a file-configured value — disabling SIEM forwarding,
        // NATS streaming, or blocked-action webhooks that the operator set in their
        // file and reasonably believes are active. The empty-string filter is kept
        // so an explicit `VAR=` still means "unset".
        if let Ok(v) = env::var("PROXILION_NATS_URL") {
            self.nats_url = Some(v).filter(|s| !s.is_empty());
        }
        if let Ok(v) = env::var("PROXILION_NATS_SUBJECT_PREFIX") {
            self.nats_subject_prefix = v;
        }
        if let Ok(v) = env::var("PROXILION_SIEM_WEBHOOK_URL") {
            self.siem_webhook_url = Some(v).filter(|s| !s.is_empty());
        }
        if let Ok(v) = env::var("PROXILION_SIEM_HMAC_KEY") {
            self.siem_hmac_key_hex = Some(v).filter(|s| !s.is_empty());
        }
        if let Ok(v) = env::var("PROXILION_SIEM_BATCH_SIZE") {
            // Leave the prior (file/default) value intact on a malformed value rather
            // than silently downgrading to per-event delivery.
            if let Ok(n) = v.parse::<usize>() {
                self.siem_batch_size = Some(n).filter(|n| *n > 1);
            }
        }
        if let Ok(v) = env::var("PROXILION_SIEM_BATCH_MAX_AGE_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                self.siem_batch_max_age_secs = n.max(1);
            }
        }
        if let Ok(v) = env::var("PROXILION_BLOCKED_WEBHOOK_URL") {
            self.blocked_webhook_url = Some(v).filter(|s| !s.is_empty());
        }
        if let Ok(v) = env::var("PROXILION_BLOCKED_WEBHOOK_HMAC_KEY") {
            self.blocked_webhook_hmac_key_hex = Some(v).filter(|s| !s.is_empty());
        }
        if matches!(
            env::var("PROXILION_DISABLE_OPERATOR_AUTH").as_deref(),
            Ok("1") | Ok("true")
        ) {
            self.operator_auth_enforced = false;
        }
        Ok(self)
    }

    /// Layer a TOML file on top of the current values. Every field is
    /// optional; absent fields leave the builder's prior value intact.
    /// Per qiuth-patterns.md §2.2, this lives **between** defaults and
    /// env so `PROXILION_*` env vars always win — operators can still
    /// override file-based config without editing the file.
    ///
    /// (Same `from_*-takes-self` naming convention as `from_env_layer`
    /// — describes the source being layered in, not a constructor.)
    #[allow(clippy::wrong_self_convention)]
    pub fn from_file(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::FileLoad {
            path: path.to_path_buf(),
            reason: format!("read: {e}"),
        })?;
        let file: FileConfig = toml::from_str(&raw).map_err(|e| ConfigError::FileLoad {
            path: path.to_path_buf(),
            reason: format!("parse: {e}"),
        })?;
        if let Some(v) = file.bind_addr {
            self.bind_addr = v.parse().map_err(|e| ConfigError::BindAddr(v.clone(), e))?;
        }
        if let Some(v) = file.tls_cert_path {
            self.tls_cert_path = v;
        }
        if let Some(v) = file.tls_key_path {
            self.tls_key_path = v;
        }
        if let Some(v) = file.database_url {
            self.database_url = Some(v);
        }
        if let Some(v) = file.trust_plane_url {
            self.trust_plane_url = v;
        }
        if let Some(v) = file.federation_bridge_url {
            self.federation_bridge_url = v;
        }
        if let Some(v) = file.log_format {
            self.log_format = if v.eq_ignore_ascii_case("pretty") {
                LogFormat::Pretty
            } else {
                LogFormat::Json
            };
        }
        if let Some(v) = file.token_encryption_key_hex {
            self.token_encryption_key_hex = Some(v);
        }
        if let Some(v) = file.google_client_id {
            self.google_client_id = Some(v);
        }
        if let Some(v) = file.google_client_secret {
            self.google_client_secret = Some(v);
        }
        if let Some(v) = file.proxy_base_url {
            self.proxy_base_url = v;
        }
        if let Some(v) = file.policy_path {
            self.policy_path = Some(v);
        }
        if let Some(v) = file.customer_domain {
            self.customer_domain = v;
        }
        if let Some(v) = file.dev_mode {
            self.dev_mode = v;
        }
        if let Some(v) = file.nats_url {
            self.nats_url = Some(v);
        }
        if let Some(v) = file.nats_subject_prefix {
            self.nats_subject_prefix = v;
        }
        if let Some(v) = file.siem_webhook_url {
            self.siem_webhook_url = Some(v);
        }
        if let Some(v) = file.siem_hmac_key_hex {
            self.siem_hmac_key_hex = Some(v);
        }
        if let Some(v) = file.siem_batch_size {
            self.siem_batch_size = Some(v).filter(|n| *n > 1);
        }
        if let Some(v) = file.siem_batch_max_age_secs {
            self.siem_batch_max_age_secs = v.max(1);
        }
        if let Some(v) = file.blocked_webhook_url {
            self.blocked_webhook_url = Some(v);
        }
        if let Some(v) = file.blocked_webhook_hmac_key_hex {
            self.blocked_webhook_hmac_key_hex = Some(v);
        }
        if let Some(v) = file.operator_auth_enforced {
            self.operator_auth_enforced = v;
        }
        Ok(self)
    }

    // --- chainable overrides (used by tests + future embed callers) ---

    #[allow(dead_code)]
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    #[allow(dead_code)]
    pub fn with_trust_plane_url(mut self, url: impl Into<String>) -> Self {
        self.trust_plane_url = url.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_federation_bridge_url(mut self, url: impl Into<String>) -> Self {
        self.federation_bridge_url = url.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = Some(url.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_token_encryption_key_hex(mut self, hex: impl Into<String>) -> Self {
        self.token_encryption_key_hex = Some(hex.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_policy_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy_path = Some(path.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_dev_mode(mut self, on: bool) -> Self {
        self.dev_mode = on;
        self
    }

    /// Finalize the builder. Runs semantic validation that env-only
    /// loading can't easily express:
    ///
    /// - `token_encryption_key_hex` is exactly 64 hex chars when present.
    /// - `trust_plane_url` / `federation_bridge_url` parse as
    ///   `http(s)://`.
    /// - `dev_mode == false` requires both cert and key paths to resolve.
    pub fn build(self) -> Result<Config, ConfigError> {
        // Token encryption key shape — defer key-material validation to
        // crypto::TokenCipher, but reject early on the cheap check.
        if let Some(hex) = self.token_encryption_key_hex.as_ref() {
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConfigError::InvalidValue {
                    field: "PROXILION_TOKEN_ENCRYPTION_KEY",
                    reason: format!("expected 64 hex chars (32 bytes), got {} chars", hex.len()),
                });
            }
        }

        // URL shape — reject obvious typos. Allow either http:// or https://.
        check_http_url("PROXILION_TRUST_PLANE_URL", &self.trust_plane_url)?;
        check_http_url(
            "PROXILION_FEDERATION_BRIDGE_URL",
            &self.federation_bridge_url,
        )?;

        // dev_mode = false → cert + key must exist on disk now.
        if !self.dev_mode {
            if !self.tls_cert_path.exists() {
                return Err(ConfigError::MissingCert(self.tls_cert_path));
            }
            if !self.tls_key_path.exists() {
                return Err(ConfigError::MissingKey(self.tls_key_path));
            }
        }

        Ok(Config {
            bind_addr: self.bind_addr,
            tls_cert_path: self.tls_cert_path,
            tls_key_path: self.tls_key_path,
            database_url: self.database_url,
            trust_plane_url: self.trust_plane_url,
            federation_bridge_url: self.federation_bridge_url,
            log_format: self.log_format,
            token_encryption_key_hex: self.token_encryption_key_hex,
            google_client_id: self.google_client_id,
            google_client_secret: self.google_client_secret,
            proxy_base_url: self.proxy_base_url,
            policy_path: self.policy_path,
            customer_domain: self.customer_domain,
            dev_mode: self.dev_mode,
            nats_url: self.nats_url,
            nats_subject_prefix: self.nats_subject_prefix,
            siem_webhook_url: self.siem_webhook_url,
            siem_hmac_key_hex: self.siem_hmac_key_hex,
            siem_batch_size: self.siem_batch_size,
            siem_batch_max_age_secs: self.siem_batch_max_age_secs,
            blocked_webhook_url: self.blocked_webhook_url,
            blocked_webhook_hmac_key_hex: self.blocked_webhook_hmac_key_hex,
            operator_auth_enforced: self.operator_auth_enforced,
        })
    }
}

/// On-disk TOML schema. Every field is optional — operators only set
/// what they want to override. Field names match the env-var conceptual
/// model (without the `PROXILION_` prefix and in snake_case) so a
/// `bind_addr = "..."` line corresponds to `PROXILION_BIND_ADDR`.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    bind_addr: Option<String>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    database_url: Option<String>,
    trust_plane_url: Option<String>,
    federation_bridge_url: Option<String>,
    log_format: Option<String>,
    token_encryption_key_hex: Option<String>,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
    proxy_base_url: Option<String>,
    policy_path: Option<PathBuf>,
    customer_domain: Option<String>,
    dev_mode: Option<bool>,
    nats_url: Option<String>,
    nats_subject_prefix: Option<String>,
    siem_webhook_url: Option<String>,
    siem_hmac_key_hex: Option<String>,
    siem_batch_size: Option<usize>,
    siem_batch_max_age_secs: Option<u64>,
    blocked_webhook_url: Option<String>,
    blocked_webhook_hmac_key_hex: Option<String>,
    operator_auth_enforced: Option<bool>,
}

fn check_http_url(field: &'static str, url: &str) -> Result<(), ConfigError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ConfigError::InvalidValue {
            field,
            reason: format!("expected http:// or https:// URL, got {url:?}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_endpoint_strips_secret_bearing_url_parts() {
        // Slack webhook: the token in the path must not survive. (The path
        // segments are deliberately NOT in Slack's real T…/B…/<token> shape so
        // GitHub push-protection doesn't flag this fixture as a live secret;
        // what we assert is that everything after the host is dropped.)
        let slack = "https://hooks.slack.com/services/TEAMID/CHANID/path-token-fixture";
        let r = redacted_endpoint(slack);
        assert_eq!(r, "https://hooks.slack.com");
        assert!(!r.contains("path-token"), "path token leaked: {r}");

        // Generic webhook with auth in query.
        let wh = redacted_endpoint("https://hooks.example.com:8443/ingest?token=s3cr3t");
        assert_eq!(wh, "https://hooks.example.com:8443");
        assert!(!wh.contains("s3cr3t"), "query secret leaked: {wh}");

        // NATS userinfo credentials must not survive.
        let nats = redacted_endpoint("nats://user:p%40ss@nats.internal:4222");
        assert_eq!(nats, "nats://nats.internal:4222");
        assert!(
            !nats.contains("p%40ss") && !nats.contains("user"),
            "userinfo leaked: {nats}"
        );

        // Unparseable input collapses to a fixed placeholder (never echoed).
        assert_eq!(redacted_endpoint("not a url"), "(unparseable url)");
    }

    #[test]
    fn defaults_build_in_dev_mode() {
        let c = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .build()
            .unwrap();
        assert_eq!(c.bind_addr.to_string(), "0.0.0.0:8443");
        assert_eq!(c.trust_plane_url, "http://trust-plane:8080");
        assert!(c.operator_auth_enforced);
        assert_eq!(c.customer_domain, "example.com");
    }

    #[test]
    fn build_rejects_bad_token_encryption_key() {
        let r = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_token_encryption_key_hex("deadbeef")
            .build();
        let err = r.unwrap_err();
        match err {
            ConfigError::InvalidValue { field, .. } => {
                assert_eq!(field, "PROXILION_TOKEN_ENCRYPTION_KEY")
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn build_accepts_valid_token_encryption_key() {
        let hex64 = "0".repeat(64);
        let c = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_token_encryption_key_hex(&hex64)
            .build()
            .unwrap();
        assert_eq!(c.token_encryption_key_hex.unwrap().len(), 64);
    }

    #[test]
    fn build_rejects_non_http_trust_plane_url() {
        let r = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_trust_plane_url("ftp://nope")
            .build();
        let err = r.unwrap_err();
        match err {
            ConfigError::InvalidValue { field, .. } => {
                assert_eq!(field, "PROXILION_TRUST_PLANE_URL")
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn build_requires_cert_when_not_dev_mode() {
        let r = ConfigBuilder::defaults().with_dev_mode(false).build();
        let err = r.unwrap_err();
        assert!(matches!(err, ConfigError::MissingCert(_)));
    }

    #[test]
    fn from_file_overrides_defaults() {
        let dir = std::env::temp_dir().join(format!("proxilion-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxilion.toml");
        std::fs::write(
            &path,
            r#"
bind_addr = "127.0.0.1:7777"
trust_plane_url = "https://tp.internal:9000"
customer_domain = "acme.example"
dev_mode = true
operator_auth_enforced = false
"#,
        )
        .unwrap();
        let c = ConfigBuilder::defaults()
            .from_file(&path)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(c.bind_addr.to_string(), "127.0.0.1:7777");
        assert_eq!(c.trust_plane_url, "https://tp.internal:9000");
        assert_eq!(c.customer_domain, "acme.example");
        assert!(c.dev_mode);
        assert!(!c.operator_auth_enforced);
    }

    #[test]
    fn from_env_layer_does_not_clobber_file_set_optional_fields_when_env_unset() {
        // Regression: nats_url / siem_webhook_url / siem_hmac_key_hex /
        // blocked_webhook_url / blocked_webhook_hmac_key_hex are Option-valued
        // AND settable from the TOML file, which is layered BEFORE env. An
        // unconditional `self.x = env::var(..).ok().filter(..)` would wipe the
        // file value to None when the env var is unset — silently disabling SIEM
        // forwarding / NATS streaming / blocked-action webhooks the operator
        // configured in their file. Skip (don't mutate process-global env) on the
        // rare chance these vars are set in this process, so we exercise exactly
        // the "env unset" path.
        for v in [
            "PROXILION_NATS_URL",
            "PROXILION_SIEM_WEBHOOK_URL",
            "PROXILION_SIEM_HMAC_KEY",
            "PROXILION_BLOCKED_WEBHOOK_URL",
            "PROXILION_BLOCKED_WEBHOOK_HMAC_KEY",
        ] {
            if std::env::var(v).is_ok() {
                return;
            }
        }
        let dir = std::env::temp_dir().join(format!("proxilion-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxilion.toml");
        std::fs::write(
            &path,
            r#"
dev_mode = true
nats_url = "nats://nats.internal:4222"
siem_webhook_url = "https://siem.internal/ingest"
siem_hmac_key_hex = "00112233445566778899aabbccddeeff"
blocked_webhook_url = "https://soc.internal/blocked"
blocked_webhook_hmac_key_hex = "ffeeddccbbaa99887766554433221100"
"#,
        )
        .unwrap();
        let c = ConfigBuilder::defaults()
            .from_file(&path)
            .unwrap()
            .from_env_layer()
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(c.nats_url.as_deref(), Some("nats://nats.internal:4222"));
        assert_eq!(
            c.siem_webhook_url.as_deref(),
            Some("https://siem.internal/ingest")
        );
        assert_eq!(
            c.siem_hmac_key_hex.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            c.blocked_webhook_url.as_deref(),
            Some("https://soc.internal/blocked")
        );
        assert_eq!(
            c.blocked_webhook_hmac_key_hex.as_deref(),
            Some("ffeeddccbbaa99887766554433221100")
        );
    }

    #[test]
    fn from_file_rejects_unknown_field() {
        let dir = std::env::temp_dir().join(format!("proxilion-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "totally_unknown_key = \"x\"\n").unwrap();
        let err = ConfigBuilder::defaults().from_file(&path).unwrap_err();
        assert!(matches!(err, ConfigError::FileLoad { .. }), "got {err:?}");
    }

    #[test]
    fn from_file_missing_path() {
        let err = ConfigBuilder::defaults()
            .from_file("/no/such/path/proxilion.toml")
            .unwrap_err();
        assert!(matches!(err, ConfigError::FileLoad { .. }), "got {err:?}");
    }

    #[test]
    fn example_toml_parses_with_defaults_only() {
        // The shipped `config/proxilion.example.toml` is documentation
        // for operators — every field is commented out, so loading it
        // must produce a builder identical to `defaults()`. This
        // test pins that contract: if a future change adds a new
        // required field to FileConfig without updating the example,
        // or if a comment-out drifts and a field accidentally becomes
        // active, this test trips. Repo-relative path is fine — cargo
        // sets CARGO_MANIFEST_DIR to the crate root.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let example = std::path::Path::new(manifest)
            .join("..")
            .join("..")
            .join("config")
            .join("proxilion.example.toml");
        let c = ConfigBuilder::defaults()
            .from_file(&example)
            .expect("example TOML must parse")
            .with_dev_mode(true)
            .build()
            .expect("example TOML must produce a valid Config");
        // Sanity check: the example didn't accidentally activate a
        // field that would shift behavior from defaults.
        assert_eq!(c.bind_addr.to_string(), "0.0.0.0:8443");
        assert_eq!(c.trust_plane_url, "http://trust-plane:8080");
        assert_eq!(c.customer_domain, "example.com");
        assert!(c.operator_auth_enforced);
    }

    #[test]
    fn programmatic_overrides_compose() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let c = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_bind_addr(addr)
            .with_database_url("postgres://localhost/test")
            .with_policy_path("/tmp/p.yaml")
            .build()
            .unwrap();
        assert_eq!(c.bind_addr, addr);
        assert_eq!(c.database_url.as_deref(), Some("postgres://localhost/test"));
        assert_eq!(c.policy_path.unwrap().to_string_lossy(), "/tmp/p.yaml");
    }

    #[test]
    fn check_http_url_accepts_http_and_https() {
        // Both schemes are allowed — operators commonly run http:// inside
        // a trust boundary (compose network, k8s service mesh) and https://
        // when terminating at an external load balancer. Pin both.
        assert!(check_http_url("X", "http://internal.svc:8080").is_ok());
        assert!(check_http_url("X", "https://trust.example.com").is_ok());
    }

    #[test]
    fn check_http_url_rejects_other_schemes_and_surfaces_field_name() {
        // The field name is what the operator-facing error message
        // surfaces — pin that `field` round-trips through the error
        // variant unchanged (Grafana / setup-status keys on `field`).
        for bad in &["ftp://x", "file:///etc/passwd", "ws://host", "just-a-host"] {
            let err = check_http_url("PROXILION_X", bad).unwrap_err();
            match err {
                ConfigError::InvalidValue { field, reason } => {
                    assert_eq!(field, "PROXILION_X");
                    assert!(reason.contains("http://"), "reason: {reason}");
                    assert!(reason.contains(bad), "reason: {reason}");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        }
    }

    #[test]
    fn build_rejects_non_http_federation_bridge_url() {
        // Symmetric to the trust-plane URL test — both URLs must pass the
        // http(s) shape check. A regression that only ran the check on
        // the trust-plane URL would let an `ftp://` bridge URL slip
        // through.
        let r = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_federation_bridge_url("ftp://nope")
            .build();
        let err = r.unwrap_err();
        match err {
            ConfigError::InvalidValue { field, .. } => {
                assert_eq!(field, "PROXILION_FEDERATION_BRIDGE_URL");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_token_encryption_key_with_non_hex_chars() {
        // Length is right (64 chars) but two are not hex — operators
        // sometimes paste a base64-encoded value by mistake. Pin that
        // the alphabet check fails alongside the length check.
        let mut s = "0".repeat(62);
        s.push_str("ZZ");
        let err = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .with_token_encryption_key_hex(s)
            .build()
            .unwrap_err();
        match err {
            ConfigError::InvalidValue { field, reason } => {
                assert_eq!(field, "PROXILION_TOKEN_ENCRYPTION_KEY");
                // The reason mentions length even on non-hex input
                // (the check is `len != 64 || !is_hex`); pin the cap.
                assert!(reason.contains("64"), "reason: {reason}");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn build_requires_key_when_only_cert_exists_in_prod_mode() {
        // Symmetric to `build_requires_cert_when_not_dev_mode`. The cert
        // file path defaults to `./certs/cert.pem`, the key path to
        // `./certs/key.pem`. Create the cert but not the key under a
        // temp dir; the build must surface MissingKey, not MissingCert.
        let dir = std::env::temp_dir().join(format!("proxilion-cfg-key-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, "fake cert").unwrap();
        // Use the file-load path to inject the temp paths since the
        // builder doesn't expose `with_tls_*` setters directly.
        let toml_path = dir.join("c.toml");
        std::fs::write(
            &toml_path,
            format!(
                "tls_cert_path = {:?}\ntls_key_path = {:?}\ndev_mode = false\n",
                cert.display().to_string(),
                key.display().to_string(),
            ),
        )
        .unwrap();
        let err = ConfigBuilder::defaults()
            .from_file(&toml_path)
            .unwrap()
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::MissingKey(_)), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_error_bind_addr_display_carries_raw_input_and_parse_message() {
        // The BindAddr variant carries both the raw operator input (so
        // they can spot the typo without scrolling back through env) and
        // the underlying parse error (so they know whether the port is
        // out of range vs. the host is malformed). Pin both substrings —
        // a future Display refactor that hid either field would silently
        // strip operator-actionable triage info from the bootstrap log.
        let raw = "not-an-addr:99999".to_string();
        let parse_err: std::net::AddrParseError =
            "not-an-addr:99999".parse::<SocketAddr>().unwrap_err();
        let e = ConfigError::BindAddr(raw.clone(), parse_err);
        let s = e.to_string();
        assert!(s.contains("not-an-addr:99999"), "display: {s}");
        // The thiserror template is `invalid bind addr {0:?}: {1}` — the
        // raw input is debug-formatted (quoted) so the substring above
        // still matches. The trailing `{1}` is the AddrParseError's
        // Display, which always carries the word "invalid" — pin that
        // the parse-error half is rendered (not dropped to `_`).
        assert!(s.contains("invalid"), "display: {s}");
    }

    #[test]
    fn from_file_invalid_bind_addr_surfaces_bind_addr_error_variant() {
        // The from_file path runs the same `.parse::<SocketAddr>()` as
        // the env-layer path. The existing `from_file_overrides_defaults`
        // test covers the happy path; this test pins the negative — a
        // malformed bind_addr line in the TOML must surface
        // `ConfigError::BindAddr` (not collapse to `FileLoad` or
        // `InvalidValue`). A regression that wrapped the parse error in
        // `FileLoad` for "consistency" would silently change which
        // variant operator dashboards key on.
        let dir =
            std::env::temp_dir().join(format!("proxilion-cfg-bad-addr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, "bind_addr = \"definitely-not-an-addr\"\n").unwrap();
        let err = ConfigBuilder::defaults().from_file(&path).unwrap_err();
        match err {
            ConfigError::BindAddr(raw, _) => {
                assert_eq!(raw, "definitely-not-an-addr");
            }
            other => panic!("expected BindAddr variant, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_file_log_format_pretty_value_selects_pretty_variant() {
        // The `eq_ignore_ascii_case("pretty")` branch is operator-facing
        // — `pretty` is what local-dev TOML files set so log lines are
        // human-readable. Pin the Pretty variant on both `"pretty"`
        // (lowercase) and `"Pretty"` (mixed-case) inputs since the
        // comparison is case-insensitive — a refactor that tightened to
        // case-sensitive would silently break every existing operator's
        // capitalized config without surfacing a parse error.
        for raw in &["pretty", "Pretty", "PRETTY"] {
            let dir =
                std::env::temp_dir().join(format!("proxilion-cfg-pretty-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("c.toml");
            std::fs::write(&path, format!("log_format = {raw:?}\n")).unwrap();
            let c = ConfigBuilder::defaults()
                .from_file(&path)
                .unwrap()
                .with_dev_mode(true)
                .build()
                .unwrap();
            assert!(matches!(c.log_format, LogFormat::Pretty), "input: {raw}");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn from_file_log_format_unknown_value_falls_back_to_json_no_error() {
        // The else-branch on `log_format` collapses every non-"pretty"
        // value (including garbage) to JSON rather than surfacing an
        // error. Pin both halves of the contract: the build succeeds
        // (no parse error from a typo) and the variant is JSON. A
        // refactor that tightened this into a closed enum would silently
        // start rejecting deployments that carry a typo'd log_format
        // line — a hard cutover that the docs page hasn't warned about.
        let dir =
            std::env::temp_dir().join(format!("proxilion-cfg-bad-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, "log_format = \"compact-but-unknown\"\n").unwrap();
        let c = ConfigBuilder::defaults()
            .from_file(&path)
            .unwrap()
            .with_dev_mode(true)
            .build()
            .unwrap();
        assert!(matches!(c.log_format, LogFormat::Json));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_file_siem_batch_size_one_collapses_to_none_via_gt_one_filter() {
        // The `.filter(|n| *n > 1)` predicate intentionally collapses
        // `siem_batch_size = 1` to None — a 1-event batch is identical
        // to the unbatched path and the spawn of the flush loop is
        // wasted work. Pin both branches: 1 → None (collapsed), 5 →
        // Some(5) (kept). A regression to `>= 1` would silently spawn
        // the flush loop on every install with the documented
        // "disable batching" sentinel, while `> 5` would break the
        // common low-volume tuning at 2 or 3.
        for (n, want) in &[(1_usize, None), (5, Some(5))] {
            let dir = std::env::temp_dir()
                .join(format!("proxilion-cfg-siem-{n}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("c.toml");
            std::fs::write(&path, format!("siem_batch_size = {n}\n")).unwrap();
            let c = ConfigBuilder::defaults()
                .from_file(&path)
                .unwrap()
                .with_dev_mode(true)
                .build()
                .unwrap();
            assert_eq!(c.siem_batch_size, *want, "input: {n}");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn from_file_siem_batch_max_age_secs_zero_clamps_to_one() {
        // The `.max(1)` clamp on `siem_batch_max_age_secs` prevents a
        // 0-second flush interval from busy-looping the forwarder. Pin
        // both the clamp (0 → 1) and the passthrough (30 → 30) so a
        // refactor that dropped the clamp would surface here as a
        // 0-second value rather than as production CPU pegged at
        // 100% on the first low-flag operator misconfiguration.
        for (raw, want) in &[(0_u64, 1_u64), (30, 30), (1, 1)] {
            let dir = std::env::temp_dir()
                .join(format!("proxilion-cfg-age-{raw}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("c.toml");
            std::fs::write(&path, format!("siem_batch_max_age_secs = {raw}\n")).unwrap();
            let c = ConfigBuilder::defaults()
                .from_file(&path)
                .unwrap()
                .with_dev_mode(true)
                .build()
                .unwrap();
            assert_eq!(c.siem_batch_max_age_secs, *want, "input: {raw}");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn config_error_display_strings_include_field_or_path_context() {
        // Operator-facing error messages — the setup-status path renders
        // these verbatim. Pin the substrings the docs page keys on.
        let e = ConfigError::InvalidValue {
            field: "PROXILION_TRUST_PLANE_URL",
            reason: "bad scheme".into(),
        };
        let s = e.to_string();
        assert!(s.contains("PROXILION_TRUST_PLANE_URL"));
        assert!(s.contains("bad scheme"));

        let e = ConfigError::MissingCert(std::path::PathBuf::from("/etc/certs/cert.pem"));
        let s = e.to_string();
        assert!(s.contains("TLS cert"));
        assert!(s.contains("/etc/certs/cert.pem"));

        let e = ConfigError::MissingKey(std::path::PathBuf::from("/etc/certs/key.pem"));
        let s = e.to_string();
        assert!(s.contains("TLS key"));
        assert!(s.contains("/etc/certs/key.pem"));

        let e = ConfigError::FileLoad {
            path: std::path::PathBuf::from("/tmp/proxilion.toml"),
            reason: "syntax error at line 3".into(),
        };
        let s = e.to_string();
        assert!(s.contains("/tmp/proxilion.toml"));
        assert!(s.contains("syntax error at line 3"));
    }

    #[test]
    fn config_and_config_builder_and_log_format_and_config_error_send_sync_static() {
        // `Config` is constructed at boot then cloned into AppState; the
        // axum router + tokio task boundaries require (Send + Sync + 'static).
        // `ConfigBuilder` lives the same flow on the embed path. `LogFormat`
        // is held inside Config and propagated into the tracing subscriber
        // init. `ConfigError` bubbles through `anyhow::Error` chains at the
        // `Config::load()` boot path (anyhow's blanket impl requires the
        // three-trait combo). A refactor that gave any of them an `Rc<...>`
        // field "for cheap shared boot config" would break Send + Sync but
        // surface at a far-removed `tower::Service` trait-bound at the
        // router assembly site rather than at this file. Pin all four
        // bounds here so the boundary fails fast — symmetric to the
        // `auth_state_and_fail_and_refresh_coordinator_are_send_sync_static_for_axum_boundary`
        // pin on `crates/proxy/src/auth_middleware.rs`.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<Config>();
        require_send_sync_static::<ConfigBuilder>();
        require_send_sync_static::<LogFormat>();
        require_send_sync_static::<ConfigError>();
    }

    #[test]
    fn log_format_derives_copy_and_debug_for_zero_alloc_field_propagation() {
        // `LogFormat` derives `Copy + Clone + Debug` — load-bearing for the
        // `Config { log_format, .. }` propagation path: the boot routine
        // reads `cfg.log_format` and hands it to the tracing subscriber
        // init by value, relying on Copy to avoid moving out of `cfg`
        // (which is still needed for downstream wiring). A refactor that
        // dropped `Copy` "for explicit clone semantics" would surface at
        // every `let f = cfg.log_format;` site as a move-out-of-borrowed
        // error after a partial-move on `cfg`. Pin the trait bound via a
        // generic fn whose signature requires Copy AND Debug, on both
        // variants, AND pin Debug surfaces the variant name for grep
        // (operator logs render `?cfg` and bucket on `Json` / `Pretty`).
        fn require_copy_debug<T: Copy + std::fmt::Debug>(_: T) {}
        require_copy_debug(LogFormat::Json);
        require_copy_debug(LogFormat::Pretty);
        // Debug carries the variant name byte-equal (not a numeric fallback).
        assert_eq!(format!("{:?}", LogFormat::Json), "Json");
        assert_eq!(format!("{:?}", LogFormat::Pretty), "Pretty");
        // Copy semantics: take the value, then take it again — the second
        // take would fail with a move error if Copy were dropped.
        let f = LogFormat::Json;
        let _a = f;
        let _b = f;
    }

    #[test]
    fn config_error_debug_carries_all_five_variant_names_for_grep_bucketing() {
        // Operator log filters bucket boot failures by Debug variant name
        // (`?err` rendering in the `Config::load()` boot path's match
        // arm). The existing
        // `config_error_display_strings_include_field_or_path_context` pin
        // walks DISPLAY substrings but does NOT pin the Debug variant
        // names — a manual Debug impl that collapsed all five variants
        // to `ConfigError(_)` "for compact boot logs" would silently
        // break grep-based alerting that splits "TLS cert missing"
        // (operational; redeploy with certs) from "bad bind addr"
        // (operator typo in env) from "config file syntax error"
        // (operator typo in TOML). Pin all five variant names render in
        // Debug — symmetric to the `executor_error_debug_carries_all_five_variant_names_for_grep_bucketing`
        // pin on `crates/proxy/src/pic/executor.rs`.
        let bind =
            ConfigError::BindAddr("bad".to_string(), "bad".parse::<SocketAddr>().unwrap_err());
        assert!(format!("{bind:?}").contains("BindAddr"));
        let cert = ConfigError::MissingCert(PathBuf::from("/x"));
        assert!(format!("{cert:?}").contains("MissingCert"));
        let key = ConfigError::MissingKey(PathBuf::from("/y"));
        assert!(format!("{key:?}").contains("MissingKey"));
        let inv = ConfigError::InvalidValue {
            field: "F",
            reason: "r".into(),
        };
        assert!(format!("{inv:?}").contains("InvalidValue"));
        let file = ConfigError::FileLoad {
            path: PathBuf::from("/z"),
            reason: "r".into(),
        };
        assert!(format!("{file:?}").contains("FileLoad"));
    }

    #[test]
    fn config_error_invalid_value_field_is_static_str_lifetime_for_zero_alloc_log_filter() {
        // `ConfigError::InvalidValue.field` is `&'static str` (not
        // `String`) — load-bearing for the operator-facing setup-status
        // page which reads the field name through to a Grafana panel
        // label without allocation, AND for the docs-page deep link
        // that keys on the env-var name as a stable string ID. A
        // refactor that widened to `String` "for consistency with
        // reason" would silently land an allocation per boot error AND
        // could let a refactor smuggle a non-literal field name (e.g.
        // a `format!("PROXILION_{kind}_URL")` "for ergonomic URL field
        // generation") which would break the docs deep-link's stable
        // anchor. Pin the &'static str lifetime via a generic fn whose
        // signature requires the 'static bound. Symmetric to the
        // `check_item_id_field_is_static_str_for_zero_alloc_logging`
        // pin on `crates/proxy/src/api/setup.rs`.
        fn require_static_str(_: &'static str) {}
        let e = ConfigError::InvalidValue {
            field: "PROXILION_TRUST_PLANE_URL",
            reason: "bad scheme".into(),
        };
        if let ConfigError::InvalidValue { field, .. } = e {
            require_static_str(field);
            // And the literal flows through unchanged byte-for-byte.
            assert_eq!(field, "PROXILION_TRUST_PLANE_URL");
        } else {
            panic!("expected InvalidValue variant");
        }
    }

    #[test]
    fn config_error_implements_std_error_trait_via_dyn_cast_with_leaf_source_none_on_simple_variants()
     {
        // ConfigError flows through `anyhow::Error` chains at the boot
        // path — `anyhow::Error::from` requires the `std::error::Error`
        // trait, which the `thiserror::Error` derive lands. The existing
        // `config_error_display_strings_include_field_or_path_context`
        // pin walks Display only; pin the `std::error::Error` trait via
        // dyn-cast on the four leaf variants (InvalidValue / MissingCert
        // / MissingKey / FileLoad — all carry inner data but none
        // chains a `#[source]`/`#[from]` to another error). A refactor
        // that swapped `#[derive(thiserror::Error)]` for a hand-rolled
        // `impl Display` "for less macro surface" would surface here at
        // the trait-object cast rather than at a far-removed call site.
        // Pin `source() == None` on each leaf so a future refactor that
        // wrapped any of them with a `#[source]` inner would surface as
        // a chain-walk shape change. (BindAddr carries an
        // `AddrParseError` not via `#[source]` so it ALSO has
        // `source() == None`.) Symmetric to the
        // `pkce_error_source_is_none_for_both_variants_leaf_contract`
        // pin on `crates/proxy/src/crypto/pkce.rs`.
        for e in [
            ConfigError::InvalidValue {
                field: "F",
                reason: "r".into(),
            },
            ConfigError::MissingCert(PathBuf::from("/x")),
            ConfigError::MissingKey(PathBuf::from("/y")),
            ConfigError::FileLoad {
                path: PathBuf::from("/z"),
                reason: "r".into(),
            },
            ConfigError::BindAddr("bad".into(), "bad".parse::<SocketAddr>().unwrap_err()),
        ] {
            let dyn_err: &dyn std::error::Error = &e;
            // Display surfaces something non-empty (the trait is wired).
            assert!(!dyn_err.to_string().is_empty(), "Display empty: {e:?}");
            // Each variant is a leaf — no #[source]/#[from] inner Error.
            assert!(
                std::error::Error::source(dyn_err).is_none(),
                "expected leaf source None, got Some for: {e:?}",
            );
        }
    }

    #[test]
    fn config_builder_defaults_pins_un_pinned_path_url_prefix_constants_byte_exact() {
        // The existing `defaults_build_in_dev_mode` pin walks 4 fields
        // (bind_addr / trust_plane_url / operator_auth_enforced /
        // customer_domain). The remaining defaults fields are SILENTLY
        // load-bearing for operator-onboarding scripts that read the
        // defaults via `ConfigBuilder::defaults().build()` — a refactor
        // that changed `./certs/dev.crt` to `./tls/cert.pem` "for
        // ecosystem convention" would silently break every dev workflow
        // that pre-seeded certs at the documented path. Pin the six
        // un-pinned defaults byte-exact in one sweep so a single-byte
        // drift surfaces in the test that documents the operator
        // contract. The `siem_batch_max_age_secs` default (5s) is the
        // load-bearing flush cadence that the `from_file_siem_batch_max_age_secs_zero_clamps_to_one`
        // pin tests the override path of — pin the DEFAULT here so
        // both directions are anchored.
        let c = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .build()
            .unwrap();
        assert_eq!(c.tls_cert_path, PathBuf::from("./certs/dev.crt"));
        assert_eq!(c.tls_key_path, PathBuf::from("./certs/dev.key"));
        assert_eq!(c.proxy_base_url, "https://localhost:8443");
        assert_eq!(c.federation_bridge_url, "http://federation-bridge:8081");
        assert_eq!(c.nats_subject_prefix, "actions");
        assert_eq!(c.siem_batch_max_age_secs, 5);
        // log_format defaults to JSON (operator-facing setup docs say
        // "structured-by-default; opt into pretty for local dev").
        assert!(matches!(c.log_format, LogFormat::Json));
        // The five Option-shaped defaults all None (no leaky shipped
        // credentials / no surprise webhook URLs).
        assert!(c.database_url.is_none());
        assert!(c.token_encryption_key_hex.is_none());
        assert!(c.policy_path.is_none());
        assert!(c.nats_url.is_none());
        assert!(c.siem_webhook_url.is_none());
    }

    // ─── round 289 (2026-05-26): Config/ConfigBuilder/ConfigError variant + Clone pins ───

    #[test]
    fn config_field_count_pinned_at_exactly_twenty_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // `Config` carries EXACTLY 23 fields — every one of them is
        // operator-load-bearing (env-var-driven, surfaced in the
        // `/api/v1/setup/status` panel, OR consumed at boot by the
        // server.rs wiring). Pin the field count via exhaustive
        // destructure with NO `..` rest pattern: a refactor that
        // landed a 24th field (e.g. `pub kill_switch_path:
        // Option<PathBuf>` OR `pub admin_email: Option<String>`)
        // without matching `ConfigBuilder` AND the from_env_layer
        // mapping would silently leave the new field at its
        // `Default` value despite an operator setting the
        // corresponding env var. The exhaustive destructure with no
        // rest pattern forces a new field to update this site in
        // lockstep with the loader. Symmetric to round-271 SetMode
        // + round-272 OAuthState + round-274 ParsedSend field-count
        // pins extended to this sibling operator-config struct.
        let c = ConfigBuilder::defaults()
            .with_dev_mode(true)
            .build()
            .unwrap();
        let Config {
            bind_addr: _,
            tls_cert_path: _,
            tls_key_path: _,
            database_url: _,
            trust_plane_url: _,
            federation_bridge_url: _,
            log_format: _,
            token_encryption_key_hex: _,
            google_client_id: _,
            google_client_secret: _,
            proxy_base_url: _,
            policy_path: _,
            customer_domain: _,
            dev_mode: _,
            nats_url: _,
            nats_subject_prefix: _,
            siem_webhook_url: _,
            siem_hmac_key_hex: _,
            siem_batch_size: _,
            siem_batch_max_age_secs: _,
            blocked_webhook_url: _,
            blocked_webhook_hmac_key_hex: _,
            operator_auth_enforced: _,
        } = c;
    }

    #[test]
    fn config_builder_field_count_pinned_at_exactly_twenty_three_via_exhaustive_destructure_no_rest()
     {
        // `ConfigBuilder` MUST carry the SAME 23 fields as `Config`
        // — the builder→config conversion in `ConfigBuilder::build`
        // does a 1:1 field move, so an asymmetric refactor that
        // added a field to one side and not the other would either
        // (a) compile-fail at the build site if added to Config, OR
        // (b) silently strip the new builder-side field at build
        // time if added to ConfigBuilder. Pin EXACTLY 23 via
        // exhaustive destructure to anchor BOTH sides in lockstep
        // with the sibling `Config` field-count pin. A refactor that
        // extended ConfigBuilder without matching Config (the more
        // dangerous direction — silently drops the operator's value)
        // surfaces here at compile time. Symmetric to the Config
        // 23-field pin in this same round.
        let b = ConfigBuilder::defaults();
        let ConfigBuilder {
            bind_addr: _,
            tls_cert_path: _,
            tls_key_path: _,
            database_url: _,
            trust_plane_url: _,
            federation_bridge_url: _,
            log_format: _,
            token_encryption_key_hex: _,
            google_client_id: _,
            google_client_secret: _,
            proxy_base_url: _,
            policy_path: _,
            customer_domain: _,
            dev_mode: _,
            nats_url: _,
            nats_subject_prefix: _,
            siem_webhook_url: _,
            siem_hmac_key_hex: _,
            siem_batch_size: _,
            siem_batch_max_age_secs: _,
            blocked_webhook_url: _,
            blocked_webhook_hmac_key_hex: _,
            operator_auth_enforced: _,
        } = b;
    }

    #[test]
    fn config_error_variant_count_pinned_at_exactly_five_via_exhaustive_match_no_underscore_fallback()
     {
        // `ConfigError` has EXACTLY 5 variants: BindAddr +
        // MissingCert + MissingKey + InvalidValue + FileLoad. The
        // existing `config_error_debug_carries_all_five_variant_names`
        // pin walks the Debug surface; pin the VARIANT COUNT here
        // via exhaustive match WITHOUT the `_` underscore fallback
        // — a 6th-variant landing (e.g.
        // `ConfigError::EnvAccessDenied { var: String }` for read-
        // only-fs probes OR `ConfigError::TlsKeyMismatch {…}` for
        // cert/key key-pair validation) would surface here as a
        // non-exhaustive-match compile error rather than at the
        // setup dashboard's classify-by-variant logic. Symmetric to
        // round-280 AppError 11-variant exhaustive-match pin
        // extended to this sibling boot-error type.
        fn classify(e: &ConfigError) -> &'static str {
            match e {
                ConfigError::BindAddr(_, _) => "bind_addr",
                ConfigError::MissingCert(_) => "missing_cert",
                ConfigError::MissingKey(_) => "missing_key",
                ConfigError::InvalidValue { .. } => "invalid_value",
                ConfigError::FileLoad { .. } => "file_load",
            }
        }
        let samples = [
            ConfigError::BindAddr("x".into(), "x".parse::<std::net::SocketAddr>().unwrap_err()),
            ConfigError::MissingCert(PathBuf::from("/dev/null")),
            ConfigError::MissingKey(PathBuf::from("/dev/null")),
            ConfigError::InvalidValue {
                field: "x",
                reason: "y".into(),
            },
            ConfigError::FileLoad {
                path: PathBuf::from("/dev/null"),
                reason: "y".into(),
            },
        ];
        let labels: std::collections::HashSet<&'static str> =
            samples.iter().map(classify).collect();
        assert_eq!(
            labels.len(),
            5,
            "ConfigError variant count must be exactly 5: {labels:?}"
        );
    }

    #[test]
    fn log_format_variant_count_pinned_at_exactly_two_pretty_and_json_via_exhaustive_match() {
        // `LogFormat` carries EXACTLY 2 variants: `Pretty` + `Json`.
        // The existing `from_file_log_format_pretty_value_selects_pretty_variant`
        // + `from_file_log_format_unknown_value_falls_back_to_json_no_error`
        // pins walk the env/from-file string→variant dispatch; pin
        // the VARIANT COUNT via exhaustive match with NO `_`
        // fallback here. A 3rd-variant landing (e.g. `LogFormat::Tracing`
        // for OTLP exporters OR `LogFormat::Compact` for verbose-
        // grep-style logging) would surface here as a non-exhaustive
        // match — AND would force the from_file/from_env_layer
        // string→variant tables to update in lockstep with the new
        // operator-visible label. Symmetric to round-286 SuccessorOutcome
        // 2-variant exhaustive-match pin extended to this sibling
        // boot-config enum.
        fn classify(lf: LogFormat) -> &'static str {
            match lf {
                LogFormat::Pretty => "pretty",
                LogFormat::Json => "json",
            }
        }
        let a = classify(LogFormat::Pretty);
        let b = classify(LogFormat::Json);
        assert_ne!(a, b);
        let labels: std::collections::HashSet<&'static str> = [a, b].into_iter().collect();
        assert_eq!(labels.len(), 2, "LogFormat must carry exactly 2 variants");
    }

    #[test]
    fn config_and_config_builder_both_implement_clone_via_require_for_axum_state_and_embed_path() {
        // `Config: Clone` is REQUIRED for the axum-handler State<T>
        // fan-out — the boot path constructs a Config once and clones
        // it at the per-request boundary (or holds it in Arc; either
        // way the Clone derive is the operator-visible contract).
        // `ConfigBuilder: Clone` is REQUIRED for the embed-test
        // pattern where a base builder is cloned before each
        // `.with_*(...)` override variant — the existing test
        // `programmatic_overrides_compose` constructs multiple
        // configs from a single base builder, which lean on Clone.
        // The existing `config_and_config_builder_and_log_format_and_config_error_send_sync_static`
        // pin walks Send+Sync+'static only; pin the Clone trait-bound
        // axis here so a refactor that dropped `#[derive(Clone)]`
        // from EITHER struct "for explicit Arc-management of the
        // 23-field shape" surfaces here at the type boundary rather
        // than as a confusing tower::Service trait cascade. Pin
        // BOTH simultaneously so a one-side drift surfaces. Symmetric
        // to round-279/281/285/286/287 Clone witnesses extended to
        // this config-pair.
        fn require_clone<T: Clone>() {}
        require_clone::<Config>();
        require_clone::<ConfigBuilder>();
    }

    #[test]
    fn config_load_signature_pinned_via_fn_pointer_witness_fn_returns_result_config_config_error() {
        // `Config::load() -> Result<Config, ConfigError>` is the
        // documented production entry point (see file header §
        // "Loading"). Pin via fn-pointer witness: zero-arg + owned-
        // Config + ConfigError-typed error. A refactor that widened
        // the error type to `Result<Config, anyhow::Error>` "for
        // ergonomic boot-path bubbling" would lose the structured
        // ConfigError variant the setup dashboard splits on at the
        // wire AND would break the documented production-entry-point
        // contract. A refactor to `fn load(&Env) -> Result<...>`
        // dependency-injection refactor (passing in env explicitly
        // instead of reading from std::env) would silently change
        // the call site at main.rs. Symmetric to round-272
        // GoogleClient::from_env signature pin extended to this
        // sibling boot-entry-point constructor.
        let _f: fn() -> Result<Config, ConfigError> = Config::load;
    }
}
