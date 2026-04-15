mod config;
mod error;
mod service;

use crate::config::Config;
use crate::error::AppError;
use crate::service::{
    build_signing_state, issue_token_from_headers, jwks, AppState, HealthResponse, JwksResponse,
    TokenResponse,
};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/etc/idmouse.toml"
    )]
    config_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "idmouse=info,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run().await {
        error!("{error}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config_path)?;
    config.validate()?;
    let bind_address: SocketAddr = config.bind_address.parse()?;

    let state = AppState {
        config: Arc::new(config),
        signing: Arc::new(build_signing_state()?),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/token/{name}", post(token))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn token(
    Path(name): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TokenResponse>, AppError> {
    Ok(Json(issue_token_from_headers(&state, &name, &headers)?))
}

async fn jwks_handler(State(state): State<AppState>) -> Json<JwksResponse> {
    Json(jwks(&state))
}
