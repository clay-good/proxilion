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

use crate::adapters::action_stream::{ActionStream, BroadcastingActionStream};
use crate::adapters::{AdapterState, google_calendar, google_drive, google_gmail};
use crate::forwarder::{NatsBridge, SiemForwarder, SiemHmacKey, TeeStream};
use crate::notifier::{BurstConfig, BurstSuppressor, WebhookNotifier, WebhookSecret};
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

            // Build the action-stream tee early: primary =
            // BroadcastingActionStream (DB + SSE); optional secondary sinks =
            // NATS (§3.1) + SIEM webhook (§3.3). Demo + every adapter publish
            // through the same Arc<dyn ActionStream>.
            let primary: Arc<dyn ActionStream> = Arc::new(action_stream.clone());
            let mut tee = TeeStream::new(primary);
            tee = build_nats_sink(&cfg, tee).await;
            tee = build_siem_sink(&cfg, tee);
            if tee.sink_count() == 0 {
                info!("action-stream sinks: primary only (DB + SSE)");
            } else {
                info!(sinks = tee.sink_count(), "action-stream sinks installed");
            }
            let adapter_stream: Arc<dyn ActionStream> = Arc::new(tee);

            // Demo mode: if PROXILION_DEMO=1 (or DB is empty), seed synthetic
            // history and start a slow ticker.
            if crate::demo::should_run(&core.db).await {
                let _ = crate::demo::start(adapter_stream.clone());
            }

            // Build the hot-reloadable policy handle. Initial load + watcher
            // spawn happen here so admin endpoints can talk to the same
            // ArcSwap the adapters do.
            let policy_handle = build_policy_handle(&cfg)?;
            tokio::spawn(crate::policy_handle::spawn_watcher(policy_handle.clone()));

            // Blocked-action expiry sweeper (ui-less-surfaces.md §5.7).
            // Flips `pending` rows whose `expires_at` has passed to
            // `expired` once per minute. Operates independently of the
            // notifier — no fan-out on expiry by design.
            tokio::spawn(crate::blocked_expiry::spawn(
                core.db.clone(),
                crate::blocked_expiry::DEFAULT_TICK_INTERVAL,
            ));

            // Setup-status checklist (powers /admin/setup). Always-on so the
            // operator can use it to figure out what's still missing. Mounted
            // OUTSIDE the operator_auth layer — it's a checklist for an
            // operator who hasn't issued a token yet.
            let policy_count = policy_handle.load().policy_count();
            app = app.merge(crate::api::setup::router(crate::api::setup::SetupApiState {
                db: core.db.clone(),
                google_configured: cfg.google_client_id.is_some()
                    && cfg.google_client_secret.is_some(),
                federation_bridge_url: cfg.federation_bridge_url.clone(),
                policy_path_configured: cfg.policy_path.is_some(),
                policy_count,
            }));

            // Build the /api/v1/* router behind the operator_auth middleware.
            let api_state = ApiState {
                verifier: Arc::new(PicVerifier::new(
                    auth_state.pca_cache.clone(),
                    auth_state.cat_keys.clone(),
                )),
                pca_cache: auth_state.pca_cache.clone(),
            };
            // Build the notifier bundle (webhook + slack). Each driver is
            // independently hot-swappable via `/api/v1/notifier/config`.
            // DB-stored config wins; env vars are the bootstrap fallback.
            let notifiers = build_notifiers(&cfg, &core.db, Some(&policy_handle)).await;
            let protected_api = api::router(api_state)
                .merge(crate::api::actions::router(crate::api::actions::ActionsApiState {
                    db: core.db.clone(),
                    stream: action_stream.clone(),
                    pca_cache: auth_state.pca_cache.clone(),
                }))
                .merge(crate::api::blocked::router(crate::api::blocked::BlockedApiState {
                    db: core.db.clone(),
                    pca_cache: auth_state.pca_cache.clone(),
                    pic: core.pic.clone(),
                }))
                .merge(crate::api::killswitch::router(
                    crate::api::killswitch::KillswitchApiState {
                        db: core.db.clone(),
                        kill_cache: auth_state.kill_cache.clone(),
                    },
                ))
                .merge(crate::api::policy::router(crate::api::policy::PolicyApiState {
                    policy: policy_handle.clone(),
                }))
                .merge(crate::api::notifier::router(crate::api::notifier::NotifierApiState {
                    notifiers: notifiers.clone(),
                    db: core.db.clone(),
                    proxy_base_url: cfg.proxy_base_url.clone(),
                }));
            let operator_state = crate::operator_auth::OperatorAuthState {
                db: core.db.clone(),
                enforced: cfg.operator_auth_enforced,
            };
            if !cfg.operator_auth_enforced {
                warn!(
                    "PROXILION_DISABLE_OPERATOR_AUTH=1 — /api/v1/* is unauthenticated. \
                     Dev only; never use in production."
                );
            }
            app = app.merge(protected_api.route_layer(middleware::from_fn_with_state(
                operator_state,
                crate::operator_auth::middleware,
            )));

            // Public-facing approval landing page (ui-less-surfaces.md §5.4).
            // The single-use `notifier_tokens` row IS the credential, so this
            // router lives OUTSIDE the operator_auth layer.
            let blocked_state = Arc::new(crate::api::blocked::BlockedApiState {
                db: core.db.clone(),
                pca_cache: auth_state.pca_cache.clone(),
                pic: core.pic.clone(),
            });
            app = app.merge(crate::api::notifier_public::router(
                crate::api::notifier_public::NotifierPublicState {
                    db: core.db.clone(),
                    blocked: blocked_state.clone(),
                },
            ));

            // Slack interaction webhook (ui-less-surfaces.md §5.3). Signed
            // request IS the credential; lives outside operator_auth.
            app = app.merge(crate::api::notifier_slack::router(
                crate::api::notifier_slack::SlackInteractState {
                    slack: notifiers.slack.clone(),
                    blocked: blocked_state,
                    db: core.db.clone(),
                },
            ));

            // OAuth + adapter routes layer on top, gated separately on
            // Google creds.
            if let Some(oauth_state) = build_oauth_state(&cfg, &core) {
                let adapter_state = build_adapter_state(
                    &cfg, &auth_state, &oauth_state, adapter_stream,
                    policy_handle, notifiers,
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
        kill_cache: crate::kill_cache::KillCache::new(),
    }
}

fn build_adapter_state(
    cfg: &Config,
    auth: &AuthState,
    oauth: &OAuthState,
    stream: Arc<dyn ActionStream>,
    policy: crate::policy_handle::PolicyHandle,
    notifier: crate::notifier::Notifiers,
) -> Result<AdapterState> {
    Ok(AdapterState {
        auth: auth.clone(),
        policy,
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
        stream,
        google_api_base: std::env::var("GOOGLE_API_BASE").ok(),
        customer_domain: cfg.customer_domain.clone(),
        notifier,
    })
}

async fn build_nats_sink(cfg: &Config, tee: TeeStream) -> TeeStream {
    let Some(url) = cfg.nats_url.as_deref() else {
        return tee;
    };
    match NatsBridge::connect(url, cfg.nats_subject_prefix.clone()).await {
        Ok(bridge) => {
            info!(url = %url, prefix = %cfg.nats_subject_prefix, "NATS bridge connected");
            tee.with_sink(Arc::new(bridge))
        }
        Err(e) => {
            warn!(url = %url, error = %e, "NATS bridge: connect failed; continuing without it");
            tee
        }
    }
}

fn build_policy_handle(cfg: &Config) -> Result<crate::policy_handle::PolicyHandle> {
    use std::sync::Arc;
    // Path configured → back the handle with a `FilePolicyLoader` so the
    // watcher uses the pluggable backend (qiuth-patterns.md §5).
    // Unconfigured → preserve the simple inline-empty-policy bootstrap.
    if let Some(p) = cfg.policy_path.as_ref() {
        let yaml = std::fs::read_to_string(p)
            .with_context(|| format!("reading policy file {}", p.display()))?;
        let engine = policy_engine::Engine::new(&yaml)
            .map_err(|e| anyhow::anyhow!("policy engine: {e}"))?;
        let loader = Arc::new(policy_engine::FilePolicyLoader::new(p));
        let initial_version = loader.version_token_sync().unwrap_or_default();
        Ok(crate::policy_handle::PolicyHandle::with_loader(
            engine,
            loader,
            yaml,
            initial_version,
            Some(p.clone()),
        ))
    } else {
        let yaml = String::from("[]");
        let engine = policy_engine::Engine::new(&yaml)
            .map_err(|e| anyhow::anyhow!("policy engine: {e}"))?;
        Ok(crate::policy_handle::PolicyHandle::new(engine, None, yaml))
    }
}

/// Resolve webhook URL + HMAC hex: DB row first (ui-less-surfaces.md §8.4),
/// env vars second. Returns `(url, hex)` or `None` when neither source has
/// a complete config.
async fn resolve_webhook_config(cfg: &Config, db: &sqlx::PgPool) -> Option<(String, String)> {
    // 1. DB (preferred).
    let row: Option<(bool, serde_json::Value)> =
        sqlx::query_as("SELECT enabled, config FROM notifier_config WHERE id = 'webhook'")
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    if let Some((enabled, conf)) = row {
        if !enabled {
            info!("notifier_config: webhook row exists but enabled=false — notifier disabled");
            return None;
        }
        let url = conf.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
        let hex = conf.get("hmac_key").and_then(|v| v.as_str()).map(|s| s.to_string());
        if let (Some(u), Some(h)) = (url, hex) {
            return Some((u, h));
        }
        warn!("notifier_config: webhook row missing url or hmac_key — falling back to env");
    }
    // 2. Env fallback.
    let url = cfg.blocked_webhook_url.as_deref()?.to_string();
    let hex = cfg.blocked_webhook_hmac_key_hex.as_deref()?.to_string();
    Some((url, hex))
}

async fn build_notifiers(
    cfg: &Config,
    db: &sqlx::PgPool,
    policy: Option<&crate::policy_handle::PolicyHandle>,
) -> crate::notifier::Notifiers {
    let n = crate::notifier::Notifiers::empty();

    // Webhook driver (ui-less-surfaces.md §10.3 + §8.4).
    if let Some((url, hex)) = resolve_webhook_config(cfg, db).await {
        match WebhookSecret::from_hex(&hex) {
            Ok(secret) => match WebhookNotifier::new(
                url.clone(),
                secret,
                cfg.proxy_base_url.clone(),
            ) {
                Ok(wn) => {
                    let mut suppressor = BurstSuppressor::new(BurstConfig::default());
                    if let Some(handle) = policy {
                        let handle: crate::policy_handle::PolicyHandle = handle.clone();
                        let resolver: crate::notifier::burst::BurstResolver =
                            Arc::new(move |policy_id| handle.load().burst_override_for(policy_id));
                        suppressor = suppressor.with_resolver(resolver);
                    }
                    let wn = wn.with_burst(suppressor.clone());
                    let notifier = Arc::new(wn);
                    let nfor = notifier.clone();
                    let proxy_url = cfg.proxy_base_url.clone();
                    tokio::spawn(crate::notifier::burst::spawn_flush_loop(
                        suppressor,
                        move |summary| {
                            let n = nfor.clone();
                            let url = proxy_url.clone();
                            async move {
                                let s = summary.with_details_url(&url);
                                n.notify_summary(&s).await;
                            }
                        },
                    ));
                    info!(
                        url = %url,
                        "blocked-action webhook notifier installed (with burst suppression)"
                    );
                    n.webhook.replace(Some(notifier));
                }
                Err(e) => warn!(error = %e, "WebhookNotifier build failed; webhook disabled"),
            },
            Err(e) => warn!(error = %e, "webhook HMAC key invalid; webhook disabled"),
        }
    }

    // Slack driver (ui-less-surfaces.md §5.3).
    if let Some((url, secret_text)) = resolve_slack_config(db).await {
        let secret = crate::notifier::SlackSigningSecret::new(secret_text);
        match crate::notifier::SlackNotifier::new(url.clone(), secret, cfg.proxy_base_url.clone()) {
            Ok(sn) => {
                let mut suppressor = BurstSuppressor::new(BurstConfig::default());
                if let Some(handle) = policy {
                    let handle: crate::policy_handle::PolicyHandle = handle.clone();
                    let resolver: crate::notifier::burst::BurstResolver =
                        Arc::new(move |policy_id| handle.load().burst_override_for(policy_id));
                    suppressor = suppressor.with_resolver(resolver);
                }
                let sn = sn.with_burst(suppressor.clone());
                let notifier = Arc::new(sn);
                let nfor = notifier.clone();
                let proxy_url = cfg.proxy_base_url.clone();
                tokio::spawn(crate::notifier::burst::spawn_flush_loop(
                    suppressor,
                    move |summary| {
                        let n = nfor.clone();
                        let url = proxy_url.clone();
                        async move {
                            let s = summary.with_details_url(&url);
                            n.notify_summary(&s).await;
                        }
                    },
                ));
                info!(url = %url, "blocked-action slack notifier installed (with burst suppression)");
                n.slack.replace(Some(notifier));
            }
            Err(e) => warn!(error = %e, "SlackNotifier build failed; slack disabled"),
        }
    }

    // Email driver (ui-less-surfaces.md §5.4).
    if let Some(cfg_row) = resolve_email_config(db).await {
        match crate::notifier::EmailNotifier::new_with_recipients(
            &cfg_row.smtp_url,
            &cfg_row.from,
            &cfg_row.to,
            &cfg_row.cc,
            &cfg_row.bcc,
            cfg.proxy_base_url.clone(),
            db.clone(),
        ) {
            Ok(en) => {
                info!(from = %cfg_row.from, "blocked-action email notifier installed");
                n.email.replace(Some(Arc::new(en)));
            }
            Err(e) => warn!(error = %e, "EmailNotifier build failed; email disabled"),
        }
    }

    n
}

struct EmailRowConfig {
    smtp_url: String,
    from: String,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
}

/// Read the email driver row. No env fallback (SMTP credentials belong
/// in DB only).
async fn resolve_email_config(db: &sqlx::PgPool) -> Option<EmailRowConfig> {
    let row: Option<(bool, serde_json::Value)> =
        sqlx::query_as("SELECT enabled, config FROM notifier_config WHERE id = 'email'")
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let (enabled, conf) = row?;
    if !enabled {
        return None;
    }
    let smtp_url = conf.get("smtp_url").and_then(|v| v.as_str()).map(String::from)?;
    let from = conf.get("from").and_then(|v| v.as_str()).map(String::from)?;
    // `to` may be a single string OR an array of strings.
    let to: Vec<String> = match conf.get("to") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return None,
    };
    if to.is_empty() {
        return None;
    }
    // cc / bcc: optional, same single-string-or-array shape as `to`.
    let read_list = |key: &str| -> Vec<String> {
        match conf.get(key) {
            Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    };
    let cc = read_list("cc");
    let bcc = read_list("bcc");
    Some(EmailRowConfig {
        smtp_url,
        from,
        to,
        cc,
        bcc,
    })
}

/// Read the Slack driver row. No env fallback (Slack tokens belong in DB
/// only; environment variables are too easy to leak).
async fn resolve_slack_config(db: &sqlx::PgPool) -> Option<(String, String)> {
    let row: Option<(bool, serde_json::Value)> =
        sqlx::query_as("SELECT enabled, config FROM notifier_config WHERE id = 'slack'")
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let (enabled, conf) = row?;
    if !enabled {
        return None;
    }
    let url = conf
        .get("incoming_webhook_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    let secret = conf
        .get("signing_secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    Some((url, secret))
}

fn build_siem_sink(cfg: &Config, tee: TeeStream) -> TeeStream {
    let Some(url) = cfg.siem_webhook_url.as_deref() else {
        return tee;
    };
    let Some(hex) = cfg.siem_hmac_key_hex.as_deref() else {
        warn!("PROXILION_SIEM_WEBHOOK_URL set but PROXILION_SIEM_HMAC_KEY missing — SIEM forwarder disabled");
        return tee;
    };
    let key = match SiemHmacKey::from_hex(hex) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "PROXILION_SIEM_HMAC_KEY invalid — SIEM forwarder disabled");
            return tee;
        }
    };
    match SiemForwarder::new(url.to_string(), key) {
        Ok(mut fwd) => {
            if let Some(size) = cfg.siem_batch_size {
                let interval = std::time::Duration::from_secs(cfg.siem_batch_max_age_secs);
                fwd = fwd.with_batching(size, interval);
                info!(
                    url = %url,
                    batch_size = size,
                    flush_secs = cfg.siem_batch_max_age_secs,
                    "SIEM forwarder installed (batched)"
                );
            } else {
                info!(url = %url, "SIEM forwarder installed (per-event)");
            }
            let arc_fwd = Arc::new(fwd);
            if arc_fwd.batching_enabled() {
                tokio::spawn(crate::forwarder::siem::spawn_flush_loop(arc_fwd.clone()));
            }
            tee.with_sink(arc_fwd)
        }
        Err(e) => {
            warn!(error = %e, "SIEM forwarder build failed; continuing without it");
            tee
        }
    }
}

fn adapter_router(adapter: AdapterState, auth: AuthState) -> Router {
    let drive = google_drive::router(adapter.clone());
    let gmail = google_gmail::router(adapter.clone());
    let calendar = google_calendar::router(adapter);
    drive
        .merge(gmail)
        .merge(calendar)
        .route_layer(middleware::from_fn_with_state(auth, auth_middleware))
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
