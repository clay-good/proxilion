//! Proxilion proxy entrypoint.

use anyhow::Context;
use tracing::info;

mod adapters;
mod api;
mod audit_body;
mod auth_middleware;
mod blocked;
mod blocked_expiry;
mod config;
mod crypto;
mod demo;
mod error_envelope;
mod forwarder;
mod kill_cache;
mod notifier;
mod oauth;
mod operator_auth;
mod pic;
mod policy_handle;
mod server;
mod session;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    info!("proxilion proxy starting");

    // rustls 0.23 requires explicit CryptoProvider selection.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("rustls CryptoProvider already installed");

    // Install the global Prometheus metrics recorder. `/metrics` mounted in
    // server.rs renders this recorder's snapshot on each scrape.
    //
    // We use `install_recorder()` (returns just the handle + installs the
    // recorder globally) rather than `build_recorder()` + manual
    // `set_global_recorder()` — the latter pattern is documented in
    // metrics-exporter-prometheus 0.16 but in practice the recency-tracking
    // wrapper around the recorder reaps counters between scrapes when
    // ownership crosses the manual-set boundary. `install_recorder` keeps
    // the recorder + the upkeep thread it spawns colocated, which is what
    // accumulates counter values across calls in steady state.
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("metrics recorder install failed");
    server::set_metrics_handle(handle);

    // spec.md §3.2 — `proxilion_build_info{version,git_sha,rust_version}`.
    // Gauge held at 1; the labels carry the values so Grafana can join
    // `proxilion_build_info{git_sha="..."}` against other series for
    // "what build was running when this fired" forensics.
    //
    // `GIT_SHA` and `RUSTC_VERSION` are read at compile time; CI can stamp
    // them via `RUSTFLAGS='--cfg ...'` or simpler: build with the env vars
    // set. Absent at compile time → "unknown" — fine for dev builds.
    metrics::gauge!(
        "proxilion_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
        "git_sha" => option_env!("GIT_SHA").unwrap_or("unknown"),
        "rust_version" => option_env!("RUSTC_VERSION").unwrap_or("unknown"),
    )
    .set(1.0);

    let cfg = match config::Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config error: {e:#}");
            // EX_CONFIG per sysexits.h
            std::process::exit(78);
        }
    };

    server::run(cfg).await.context("server failed")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,proxy=debug"));

    let json = std::env::var("PROXILION_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(true);

    let registry = tracing_subscriber::registry().with(env_filter);
    if json {
        registry.with(fmt::layer().json().with_target(true)).init();
    } else {
        registry.with(fmt::layer().pretty()).init();
    }
}
