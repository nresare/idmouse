mod auth;
mod config;
mod error;
mod jwt;
mod kubernetes;
mod service;
mod signing;
mod signing_kubernetes_secret;

use crate::config::Config;
use crate::error::AppError;
use crate::service::{build_app_state, AppState, HealthResponse, JwksResponse};
use crate::signing::TOKEN_TTL_SECONDS;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::Serialize;
use serde_json::{Map, Value};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/config/idmouse.toml"
    )]
    config_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "idmouse=debug,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run().await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config_path)?;
    config.validate()?;
    let bind_address: SocketAddr = config.bind_address.parse()?;

    info!(version = VERSION, config_path = %cli.config_path, "starting idmouse");

    let state = build_app_state(config)?;

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
    let bearer_token = extract_bearer_token(&headers)?;
    let source_subject = state.subject_validator.validate(&bearer_token)?;
    let mut claims = state.mapping_resolver.resolve(&name, &source_subject)?;
    add_timestamps(&mut claims)?;
    let token = state.token_builder.build(&claims)?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in: TOKEN_TTL_SECONDS,
        mapping: name,
        source_subject,
    }))
}

async fn jwks_handler(State(state): State<AppState>) -> Result<Json<JwksResponse>, AppError> {
    Ok(Json(state.jwks()?))
}

fn add_timestamps(
    claims: &mut Map<String, Value>,
) -> Result<(), AppError> {
    let issued_at = now()?;
    let expires_at = issued_at
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| AppError::Internal("token expiration overflow".to_string()))?;
    claims.insert("iat".to_string(), Value::from(issued_at));
    claims.insert("nbf".to_string(), Value::from(issued_at));
    claims.insert("exp".to_string(), Value::from(expires_at));
    Ok(())
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected a Bearer token".to_string()))?;
    if token.is_empty() {
        return Err(AppError::Unauthorized("empty bearer token".to_string()));
    }
    Ok(token.to_string())
}

fn now() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| AppError::Internal(format!("system time error: {e}")))
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub mapping: String,
    pub source_subject: String,
}
