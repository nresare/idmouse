use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = self.to_string();
        (status, Json(ErrorBody { error: &message })).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error.to_string())
    }
}
