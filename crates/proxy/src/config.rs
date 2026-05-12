//! Proxy configuration loaded from environment.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
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
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr_raw =
            env::var("PROXILION_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
        let bind_addr = bind_addr_raw
            .parse()
            .map_err(|e| ConfigError::BindAddr(bind_addr_raw.clone(), e))?;

        let tls_cert_path = env::var("PROXILION_TLS_CERT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./certs/dev.crt"));
        let tls_key_path = env::var("PROXILION_TLS_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./certs/dev.key"));

        let dev_mode = matches!(env::var("PROXILION_DEV").as_deref(), Ok("1") | Ok("true"));

        if !dev_mode {
            if !tls_cert_path.exists() {
                return Err(ConfigError::MissingCert(tls_cert_path));
            }
            if !tls_key_path.exists() {
                return Err(ConfigError::MissingKey(tls_key_path));
            }
        }

        let log_format = match env::var("PROXILION_LOG_FORMAT").as_deref() {
            Ok(v) if v.eq_ignore_ascii_case("pretty") => LogFormat::Pretty,
            _ => LogFormat::Json,
        };

        Ok(Self {
            bind_addr,
            tls_cert_path,
            tls_key_path,
            database_url: env::var("DATABASE_URL").ok(),
            trust_plane_url: env::var("PROXILION_TRUST_PLANE_URL")
                .unwrap_or_else(|_| "http://trust-plane:8080".to_string()),
            federation_bridge_url: env::var("PROXILION_FEDERATION_BRIDGE_URL")
                .unwrap_or_else(|_| "http://federation-bridge:8081".to_string()),
            log_format,
            dev_mode,
            token_encryption_key_hex: env::var("PROXILION_TOKEN_ENCRYPTION_KEY").ok(),
            google_client_id: env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            proxy_base_url: env::var("PROXILION_PUBLIC_URL")
                .unwrap_or_else(|_| "https://localhost:8443".to_string()),
            policy_path: env::var("PROXILION_POLICY_PATH").ok().map(PathBuf::from),
            customer_domain: env::var("PROXILION_CUSTOMER_DOMAIN")
                .unwrap_or_else(|_| "example.com".to_string()),
            nats_url: env::var("PROXILION_NATS_URL").ok().filter(|s| !s.is_empty()),
            nats_subject_prefix: env::var("PROXILION_NATS_SUBJECT_PREFIX")
                .unwrap_or_else(|_| "actions".to_string()),
            siem_webhook_url: env::var("PROXILION_SIEM_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            siem_hmac_key_hex: env::var("PROXILION_SIEM_HMAC_KEY").ok().filter(|s| !s.is_empty()),
            blocked_webhook_url: env::var("PROXILION_BLOCKED_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            blocked_webhook_hmac_key_hex: env::var("PROXILION_BLOCKED_WEBHOOK_HMAC_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            operator_auth_enforced: !matches!(
                env::var("PROXILION_DISABLE_OPERATOR_AUTH").as_deref(),
                Ok("1") | Ok("true")
            ),
        })
    }
}
