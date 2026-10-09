mod discovery;
mod inventory;
mod orders;
mod token_source;
mod verifier;

use std::{sync::Arc, time::Duration};
use anyhow::Context;
use axum::{routing::get, Router};
use token_source::TokenSource;
use tracing_subscriber::{fmt, EnvFilter};
use verifier::Verifier;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    fmt().with_env_filter(filter).with_ansi(ansi).init();

    let mode = env("MODE")?;
    let service_name = env("SERVICE_NAME")?;
    let sts_url = env("STS_URL")?;
    let issuer = env("ISSUER")?;
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let http = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let metadata = discovery::discover(&http, &sts_url, &issuer).await?;

    let app = match mode.as_str() {
        "inventory" => {
            let verifier = Verifier::new(http, metadata.jwks_uri, &issuer, &service_name).await?;
            inventory::router(Arc::new(verifier))
        }
        "orders" => {
            let secret_file = env("CLIENT_SECRET_FILE")?;
            let client_secret = std::fs::read_to_string(&secret_file)
                .with_context(|| format!("reading {secret_file}"))?
                .trim()
                .to_string();
            let tokens = TokenSource::new(
                http.clone(),
                metadata.token_endpoint,
                env("CLIENT_ID")?,
                client_secret,
                env("INVENTORY_AUDIENCE")?,
                env("INVENTORY_SCOPE")?,
            );
            orders::router(http, env("INVENTORY_URL")?, Arc::new(tokens))
        }
        other => anyhow::bail!("unknown MODE {other}, expected inventory or orders"),
    };
    let app = app.merge(Router::new().route("/healthz", get(|| async { "ok" })));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(%mode, %service_name, %bind_addr, "demo service listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

fn env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be set"))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
