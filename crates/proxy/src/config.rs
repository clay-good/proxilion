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

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    // Wired in later steps (sqlx pool, log-format selection moves out of main.rs).
    pub database_url: Option<String>,
    pub trust_plane_url: String,
    pub federation_bridge_url: String,
    #[allow(dead_code)]
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
    /// Backward-compat entry. Delegates to [`ConfigBuilder::defaults`] +
    /// [`ConfigBuilder::from_env_layer`] + [`ConfigBuilder::build`] —
    /// behavior is byte-identical with the prior env-only loader.
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self, ConfigError> {
        ConfigBuilder::defaults().from_env_layer()?.build()
    }

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
/// 1. **Production:** `ConfigBuilder::defaults().from_env_layer()?.build()` —
///    same as `Config::from_env()`.
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
        self.nats_url = env::var("PROXILION_NATS_URL")
            .ok()
            .filter(|s| !s.is_empty());
        if let Ok(v) = env::var("PROXILION_NATS_SUBJECT_PREFIX") {
            self.nats_subject_prefix = v;
        }
        self.siem_webhook_url = env::var("PROXILION_SIEM_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.is_empty());
        self.siem_hmac_key_hex = env::var("PROXILION_SIEM_HMAC_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        if let Ok(v) = env::var("PROXILION_SIEM_BATCH_SIZE") {
            self.siem_batch_size = v.parse::<usize>().ok().filter(|n| *n > 1);
        }
        if let Ok(v) = env::var("PROXILION_SIEM_BATCH_MAX_AGE_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                self.siem_batch_max_age_secs = n.max(1);
            }
        }
        self.blocked_webhook_url = env::var("PROXILION_BLOCKED_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.is_empty());
        self.blocked_webhook_hmac_key_hex = env::var("PROXILION_BLOCKED_WEBHOOK_HMAC_KEY")
            .ok()
            .filter(|s| !s.is_empty());
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

        // dev_mode = false → cert + key must exist on disk now. This is
        // the same behavior the prior `from_env` had inline.
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
}
