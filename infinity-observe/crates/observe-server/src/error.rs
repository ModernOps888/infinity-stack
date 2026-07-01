use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use observe_core::CoreError;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    TooManyRequests(String),
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &str, &str) {
        match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, "access_denied", m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", m),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(detail) = &self {
            tracing::error!(error = %detail, "internal server error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "internal server error"
                })),
            )
                .into_response();
        }
        let (status, code, msg) = self.parts();
        (
            status,
            Json(json!({ "error": code, "error_description": msg })),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound("resource not found".into()),
            other => ApiError::Internal(format!("database error: {other}")),
        }
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Invalid(m) => ApiError::BadRequest(m),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
