//! Proxilion proxy entrypoint.

use anyhow::Context;
use tracing::info;

mod adapters;
mod api;
mod auth_middleware;
mod config;
mod crypto;
mod demo;
mod error_envelope;
mod oauth;
mod pic;
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
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("metrics recorder already installed");
    server::set_metrics_handle(handle);

    let cfg = match config::Config::from_env() {
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
