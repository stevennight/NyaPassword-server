use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use npw_api::{code, ApiError};

/// An error answered as `{"code", "message"}` JSON.
#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code::UNAUTHORIZED, "sign in required")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, code::FORBIDDEN, "not allowed")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, code::NOT_FOUND, "not found")
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code::INVALID, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code::CONFLICT, msg)
    }
    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, code::RATE_LIMITED, "too many attempts, try again later")
    }
    pub fn login_failed() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code::LOGIN_FAILED, "wrong login, password or Secret Key")
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code::SERVER, "internal server error")
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(ApiError { code: self.code.to_string(), message: self.message })).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::internal(e)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::internal(e)
    }
}

impl From<npw_crypto::CryptoError> for AppError {
    fn from(e: npw_crypto::CryptoError) -> Self {
        AppError::invalid(e.to_string())
    }
}
