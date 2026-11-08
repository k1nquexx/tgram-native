use thiserror::Error;
use tgram_proto::{ErrorCode, RpcError, WireError};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("wire error: {0}")]
    Wire(#[from] WireError),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("authentication required")]
    Unauthorized,

    #[error("invalid username or password")]
    InvalidCredentials,

    #[error("username '{0}' is already taken")]
    UsernameTaken(String),

    #[error("chat {0} not found or access denied")]
    ChatNotFound(u64),

    #[error("rate limit exceeded, retry after {0} ms")]
    RateLimited(u32),

    #[error("payload exceeds allowed limit: {0}")]
    PayloadTooLarge(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("internal server error: {0}")]
    Internal(String),
}

impl ServerError {
    pub fn to_rpc_error(&self) -> RpcError {
        match self {
            Self::BadRequest(msg) => RpcError {
                code: ErrorCode::BadRequest as i32,
                message: msg.clone(),
                retry_after_ms: 0,
            },
            Self::Unauthorized => RpcError {
                code: ErrorCode::Unauthorized as i32,
                message: "Authentication required".to_owned(),
                retry_after_ms: 0,
            },
            Self::InvalidCredentials => RpcError {
                code: ErrorCode::InvalidLogin as i32,
                message: "Invalid username or password".to_owned(),
                retry_after_ms: 0,
            },
            Self::UsernameTaken(u) => RpcError {
                code: ErrorCode::UsernameTaken as i32,
                message: format!("Username '@{u}' is already registered"),
                retry_after_ms: 0,
            },
            Self::ChatNotFound(cid) => RpcError {
                code: ErrorCode::ChatNotFound as i32,
                message: format!("Chat #{cid} not found or access denied"),
                retry_after_ms: 0,
            },
            Self::RateLimited(retry_ms) => RpcError {
                code: ErrorCode::RateLimited as i32,
                message: "Too many requests".to_owned(),
                retry_after_ms: *retry_ms,
            },
            Self::PayloadTooLarge(msg) => RpcError {
                code: ErrorCode::PayloadTooLarge as i32,
                message: msg.clone(),
                retry_after_ms: 0,
            },
            Self::Wire(_) | Self::Database(_) | Self::Internal(_) => RpcError {
                code: ErrorCode::Internal as i32,
                message: "Internal server error".to_owned(),
                retry_after_ms: 0,
            },
        }
    }
}

pub type ServerResult<T> = Result<T, ServerError>;
