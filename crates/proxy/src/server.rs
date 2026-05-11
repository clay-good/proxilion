//! axum server: TLS termination, /healthz, graceful shutdown, request-id span.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, HeaderValue, Request},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use tokio::signal;
use tracing::{Instrument, info, info_span, warn};
use uuid::Uuid;

use crate::adapters::action_stream::BroadcastingActionStream;
use crate::adapters::{AdapterState, google_drive};
use crate::api::{self, ApiState};
use crate::auth_middleware::{AuthState, RefreshCoordinator, auth_middleware};
use crate::config::Config;
use crate::crypto::TokenCipher;
use crate::oauth::state::GoogleClient;
use crate::oauth::{self, OAuthState};
use crate::pic::{CatKeyRegistry, PcaCache, PicExecutor, PicVerifier};
use crate::session::SessionCtx;
use std::sync::Arc;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    trust_plane_url: String,
    federation_bridge_url: String,
    /// Set once the OAuth/adapter bootstrap finishes; `/healthz` probes both
    /// when present.
    readiness: Arc<std::sync::OnceLock<ReadinessProbe>>,
}

#[derive(Clone)]
struct ReadinessProbe {
    db: sqlx::PgPool,
    cat_keys: CatKeyRegistry,
}

pub async fn run(cfg: Config) -> Result<()> {
    if cfg.dev_mode {
        ensure_dev_cert(&cfg.tls_cert_path, &cfg.tls_key_path)
            .context("generating dev cert")?;
    }

    let tls = RustlsConfig::from_pem_file(&cfg.tls_cert_path, &cfg.tls_key_path)
        .await
        .with_context(|| {
            format!(
                "loading TLS material from {:?} / {:?}",
                cfg.tls_cert_path, cfg.tls_key_path
            )
        })?;

    let readiness = Arc::new(std::sync::OnceLock::<ReadinessProbe>::new());
    let state = AppState {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .context("building reqwest client")?,
        trust_plane_url: cfg.trust_plane_url.clone(),
        federation_bridge_url: cfg.federation_bridge_url.clone(),
        readiness: readiness.clone(),
    };

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state)
        // Embedded admin page (spec.md §5.4). Single static HTML bundled
        // into the binary via include_str! so the proxy stays self-contained
        // — no asset hosting, no Node, no separate process.
        .route("/admin", get(admin_page))
        .route("/admin/", get(admin_page))
        .route("/admin/setup", get(setup_page))
        .route("/admin/setup/", get(setup_page))
        // Prometheus metrics scrape target. Renders the global recorder's
        // snapshot installed in main().
        .route("/metrics", get(metrics_page));

    // Persistence + admin UI + demo + observability mount whenever we have a
    // DB. OAuth + Drive adapter additionally require Google creds. /healthz
    // works in either case so smoke probes don't need any prereqs.
    match build_core_state(&cfg).await {
        Ok(Some(core)) => {
            let auth_state = build_auth_state_from_core(&cfg, &core);
            // Single BroadcastingActionStream shared between adapter
            // (publisher) and the actions API (subscribers + history).
            let action_stream = BroadcastingActionStream::new(core.db.clone());

            // /healthz can now probe DB + CAT key.
            let _ = readiness.set(ReadinessProbe {
                db: core.db.clone(),
                cat_keys: auth_state.cat_keys.clone(),
            });

            // Demo mode: if PROXILION_DEMO=1 (or DB is empty), seed synthetic
            // history and start a slow ticker. Gives first-time visitors a
            // populated, alive UI without needing a real agent.
            if crate::demo::should_run(&core.db).await {
                let _ = crate::demo::start(action_stream.clone());
            }

            // PCA management API + actions feed — always available with a DB.
            let api_state = ApiState {
                verifier: Arc::new(PicVerifier::new(
                    auth_state.pca_cache.clone(),
                    auth_state.cat_keys.clone(),
                )),
                pca_cache: auth_state.pca_cache.clone(),
            };
            app = app.merge(api::router(api_state));
            app = app.merge(crate::api::actions::router(
                crate::api::actions::ActionsApiState {
                    db: core.db.clone(),
                    stream: action_stream.clone(),
                    pca_cache: auth_state.pca_cache.clone(),
                },
            ));

            // Setup-status checklist (powers /admin/setup). Always-on so the
            // operator can use it to figure out what's still missing.
            let policy_count = match cfg.policy_path.as_ref() {
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(yaml) => policy_engine::Engine::new(&yaml)
                        .map(|e| e.policy_count())
                        .unwrap_or(0),
                    Err(_) => 0,
                },
                None => 0,
            };
            app = app.merge(crate::api::setup::router(crate::api::setup::SetupApiState {
                db: core.db.clone(),
                google_configured: cfg.google_client_id.is_some()
                    && cfg.google_client_secret.is_some(),
                federation_bridge_url: cfg.federation_bridge_url.clone(),
                policy_path_configured: cfg.policy_path.is_some(),
                policy_count,
            }));

            // OAuth + adapter routes layer on top, gated separately on
            // Google creds.
            if let Some(oauth_state) = build_oauth_state(&cfg, &core) {
                let adapter_state = build_adapter_state(
                    &cfg, &auth_state, &oauth_state, action_stream,
                )?;
                app = app.merge(oauth::router(oauth_state));
                app = app.merge(protected_router(auth_state.clone()));
                app = app.merge(adapter_router(adapter_state, auth_state));
                info!("full set mounted (OAuth + adapters + admin + actions + PCA APIs)");
            } else {
                info!(
                    "admin + actions + PCA APIs mounted (no GOOGLE_CLIENT_ID/SECRET, so OAuth + Drive adapter skipped)"
                );
            }
        }
        Ok(None) => warn!("DATABASE_URL not set — only /healthz mounted"),
        Err(e) => warn!(error = %e, "core bootstrap failed; only /healthz mounted"),
    }

    let app = app.layer(middleware::from_fn(request_span));

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("shutdown signal received, draining (30s)");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    info!(bind = %cfg.bind_addr, "proxy listening");
    axum_server::bind_rustls(cfg.bind_addr, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .context("axum_server::serve failed")?;
    Ok(())
}

#[derive(Serialize)]
struct Check {
    ok: bool,
    detail: Option<String>,
    latency_ms: u64,
}

#[derive(Serialize)]
struct Healthz {
    ready: bool,
    version: &'static str,
    checks: std::collections::BTreeMap<&'static str, Check>,
}

async fn healthz(State(state): State<AppState>) -> (axum::http::StatusCode, Json<Healthz>) {
    let mut checks = std::collections::BTreeMap::new();

    // Critical checks decide `ready`. The federation_bridge probe is
    // informational only — the bridge service is deferred (see spec §0.4)
    // and not part of every deployment.
    checks.insert("trust_plane", probe_endpoint(&state.http, &state.trust_plane_url).await);
    if let Some(r) = state.readiness.get() {
        checks.insert("database", probe_db(&r.db).await);
        checks.insert("cat_key", probe_cat_key(&r.cat_keys).await);
    } else {
        checks.insert(
            "database",
            Check { ok: false, detail: Some("core bootstrap incomplete (no DATABASE_URL?)".into()), latency_ms: 0 },
        );
        checks.insert(
            "cat_key",
            Check { ok: false, detail: Some("core bootstrap incomplete".into()), latency_ms: 0 },
        );
    }
    let ready = checks.values().all(|c| c.ok);
    // Informational: federation-bridge probe lives outside the readiness gate.
    checks.insert(
        "federation_bridge",
        probe_endpoint(&state.http, &state.federation_bridge_url).await,
    );

    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(Healthz { ready, version: env!("CARGO_PKG_VERSION"), checks }))
}

async fn probe_endpoint(client: &reqwest::Client, url: &str) -> Check {
    let start = std::time::Instant::now();
    // GET because some upstreams (e.g. axum-based provenance-plane) don't
    // register HEAD handlers and return 404 instead of 405. Reachability is
    // what we care about, not method semantics.
    let res = client.get(url).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;
    match res {
        Ok(r) => Check {
            // 2xx/3xx → reachable & healthy. 4xx → reachable; the URL just
            // doesn't accept the probe (auth, method, etc.) — still "up".
            // 5xx → upstream is degraded.
            ok: !r.status().is_server_error(),
            detail: Some(format!("http {}", r.status().as_u16())),
            latency_ms,
        },
        Err(e) if e.is_timeout() => Check {
            ok: false,
            detail: Some("timeout".into()),
            latency_ms,
        },
        Err(_) => Check {
            ok: false,
            detail: Some("unreachable".into()),
            latency_ms,
        },
    }
}

async fn probe_db(pool: &sqlx::PgPool) -> Check {
    let start = std::time::Instant::now();
    // `1::bigint` so the scalar decode lands in i64 regardless of postgres
    // version (default for unqualified `1` is int4 which doesn't decode to i64).
    let res: Result<i64, _> = sqlx::query_scalar("SELECT 1::bigint").fetch_one(pool).await;
    Check {
        ok: res.is_ok(),
        detail: res.err().map(|e| e.to_string()),
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

async fn probe_cat_key(reg: &CatKeyRegistry) -> Check {
    let start = std::time::Instant::now();
    let res = reg.get().await;
    Check {
        ok: res.is_ok(),
        detail: res.err().map(|e| e.to_string()),
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

static METRICS_HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

pub fn set_metrics_handle(h: metrics_exporter_prometheus::PrometheusHandle) {
    let _ = METRICS_HANDLE.set(h);
}

async fn metrics_page() -> Response {
    let body = match METRICS_HANDLE.get() {
        Some(h) => h.render(),
        None => "# metrics recorder not installed\n".to_string(),
    };
    Response::builder()
        .status(200)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(axum::body::Body::from(body))
        .expect("metrics response builds")
}

async fn setup_page() -> Response {
    static HTML: &str = include_str!("../static-admin/setup.html");
    Response::builder()
        .status(200)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(HTML))
        .expect("setup admin response builds")
}

async fn admin_page() -> Response {
    // Bundled at compile time; nothing on disk in the runtime container.
    static HTML: &str = include_str!("../static-admin/index.html");
    Response::builder()
        .status(200)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(HTML))
        .expect("static admin response builds")
}

async fn request_span(mut req: Request<axum::body::Body>, next: Next) -> Response {
    let request_id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    let req_id_value =
        HeaderValue::from_str(&request_id.to_string()).expect("uuid is valid header value");
    req.headers_mut()
        .insert(&REQUEST_ID_HEADER, req_id_value.clone());

    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let span = info_span!(
        "request",
        method = %method,
        path = %path,
        request_id = %request_id,
        status = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    );

    let start = std::time::Instant::now();
    let mut resp = next.run(req).instrument(span.clone()).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    span.record("status", resp.status().as_u16());
    span.record("duration_ms", elapsed_ms);

    resp.headers_mut().insert(&REQUEST_ID_HEADER, req_id_value);
    resp
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM"),
            _ = sigint.recv() => info!("SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        info!("ctrl-c");
    }
}

fn build_auth_state_from_core(cfg: &Config, core: &CoreState) -> AuthState {
    AuthState {
        db: core.db.clone(),
        cipher: core.cipher.clone(),
        pca_cache: PcaCache::new(core.db.clone()),
        cat_keys: CatKeyRegistry::new(cfg.trust_plane_url.clone()),
        refresh_coordinator: RefreshCoordinator::default(),
        // Google fields are filled when oauth_state is built; the bearer
        // middleware's refresh path only runs after an agent has actually
        // gone through the OAuth flow, so empty strings here are inert.
        google_token_url: cfg
            .google_client_id
            .as_deref()
            .map(|_| {
                std::env::var("GOOGLE_TOKEN_URL")
                    .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into())
            })
            .unwrap_or_default(),
        google_client_id: cfg.google_client_id.clone().unwrap_or_default(),
        google_client_secret: cfg.google_client_secret.clone().unwrap_or_default(),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client"),
    }
}

fn build_adapter_state(
    cfg: &Config,
    auth: &AuthState,
    oauth: &OAuthState,
    stream: BroadcastingActionStream,
) -> Result<AdapterState> {
    let policy_yaml = match cfg.policy_path.as_ref() {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("reading policy file {}", p.display()))?,
        None => String::from("[]"),
    };
    let engine = policy_engine::Engine::new(&policy_yaml)
        .map_err(|e| anyhow::anyhow!("policy engine: {e}"))?;
    Ok(AdapterState {
        auth: auth.clone(),
        policy: Arc::new(engine),
        pic: oauth.pic.clone(),
        upstream: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!(
                "Proxilion/",
                env!("CARGO_PKG_VERSION"),
                " (+https://proxilion.com)"
            ))
            .build()
            .context("upstream reqwest client")?,
        stream: Arc::new(stream),
        google_api_base: std::env::var("GOOGLE_API_BASE").ok(),
        customer_domain: cfg.customer_domain.clone(),
    })
}

fn adapter_router(adapter: AdapterState, auth: AuthState) -> Router {
    google_drive::router(adapter).route_layer(middleware::from_fn_with_state(auth, auth_middleware))
}

/// A small router for endpoints that require a `SessionCtx`. The real meat
/// (Drive / Gmail adapters) lands in §1.3+. We mount `/internal/whoami` now
/// so the bearer middleware is exercised in CI and the wiring is testable.
fn protected_router(auth: AuthState) -> Router {
    use crate::session::SessionContext;
    async fn whoami(SessionCtx(s): SessionCtx) -> Json<serde_json::Value> {
        // SessionContext::Debug already redacts the Google token.
        let SessionContext {
            agent_session_id,
            p_0,
            leaf_pca_id,
            granted_ops,
            google_token_scope,
            ..
        } = &*s;
        Json(serde_json::json!({
            "session_id": agent_session_id,
            "p_0": p_0,
            "leaf_pca_id": leaf_pca_id,
            "granted_ops": granted_ops,
            "scope": google_token_scope,
        }))
    }
    Router::new()
        .route("/internal/whoami", get(whoami))
        .route_layer(middleware::from_fn_with_state(auth, auth_middleware))
}

/// Build the OAuth handler state, or return None if a prerequisite is missing.
/// Core persistence + crypto. Built when `DATABASE_URL` is set; everything
/// downstream (admin UI, demo, /healthz dependency probes, actions API, PCA
/// API) needs only this.
struct CoreState {
    db: sqlx::PgPool,
    cipher: Arc<TokenCipher>,
    pic: PicExecutor,
}

async fn build_core_state(cfg: &Config) -> Result<Option<CoreState>> {
    let Some(db_url) = cfg.database_url.as_deref() else {
        return Ok(None);
    };

    // Auto-generate a token encryption key if missing. Persistence path: we
    // store it via DB-side `current_setting` so a restart keeps the same key.
    // The DB persistence happens after migrations; for first boot we just
    // generate and the operator can later set PROXILION_TOKEN_ENCRYPTION_KEY
    // to lock it in. (Production deploys should always set it explicitly.)
    let key_bytes: [u8; 32] = match cfg.token_encryption_key_hex.as_deref() {
        Some(hex) => hex_decode_32(hex)
            .context("PROXILION_TOKEN_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")?,
        None => {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
            warn!(
                "PROXILION_TOKEN_ENCRYPTION_KEY not set — generating an ephemeral key. \
                 Encrypted tokens will not survive a restart. Set this var to persist."
            );
            b
        }
    };
    let cipher = TokenCipher::from_bytes(&key_bytes).context("invalid token encryption key")?;

    let pool = sqlx::PgPool::connect(db_url)
        .await
        .with_context(|| format!("connecting to {db_url}"))?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("running migrations")?;

    let pic = PicExecutor::dev_ephemeral(cfg.trust_plane_url.clone())
        .map_err(|e| anyhow::anyhow!("pic executor: {e}"))?;

    Ok(Some(CoreState {
        db: pool,
        cipher: Arc::new(cipher),
        pic,
    }))
}

/// Google OAuth client config. Built when GOOGLE_CLIENT_ID / SECRET are set;
/// gates the OAuth router and the Drive adapter, nothing else.
fn build_oauth_state(cfg: &Config, core: &CoreState) -> Option<OAuthState> {
    let (google_id, google_secret) = match (
        cfg.google_client_id.as_deref(),
        cfg.google_client_secret.as_deref(),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };
    Some(OAuthState {
        db: core.db.clone(),
        cipher: core.cipher.clone(),
        pic: core.pic.clone(),
        google: GoogleClient {
            client_id: google_id.to_string(),
            client_secret: google_secret.to_string(),
            auth_url: std::env::var("GOOGLE_AUTH_URL")
                .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".into()),
            token_url: std::env::var("GOOGLE_TOKEN_URL")
                .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
        },
        federation_bridge_authorize_url: format!("{}/authorize", cfg.federation_bridge_url),
        proxy_base_url: cfg.proxy_base_url.clone(),
    })
}

fn hex_decode_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", hex.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("hex char pair {i}: {e}"))?;
    }
    Ok(out)
}

fn ensure_dev_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    warn!(?cert_path, ?key_path, "PROXILION_DEV=1: generating self-signed cert");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .context("rcgen failed")?;
    let mut cf = std::fs::File::create(cert_path)?;
    cf.write_all(cert.cert.pem().as_bytes())?;
    let mut kf = std::fs::File::create(key_path)?;
    kf.write_all(cert.key_pair.serialize_pem().as_bytes())?;
    Ok(())
}
