///! Session Store Abstraction
///!
///! Provides a trait-based abstraction for session storage, allowing
///! multiple backend implementations (Redis, PostgreSQL, In-Memory).

use crate::SessionState;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionStoreError {
    #[error("Session not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Storage backend error: {0}")]
    BackendError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

pub type Result<T> = std::result::Result<T, SessionStoreError>;

/// Session store trait - abstraction over different storage backends
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Get a session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionState>>;

    /// Save/update a session
    async fn put_session(&self, session: &SessionState) -> Result<()>;

    /// Delete a session
    async fn delete_session(&self, session_id: &str) -> Result<()>;

    /// List all session IDs for a user
    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<String>>;

    /// Get all sessions for a user
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionState>>;

    /// Check if session exists
    async fn exists(&self, session_id: &str) -> Result<bool> {
        Ok(self.get_session(session_id).await?.is_some())
    }

    /// Get session count for user
    async fn count_user_sessions(&self, user_id: &str) -> Result<usize> {
        Ok(self.list_user_sessions(user_id).await?.len())
    }
}

// Store implementations
#[cfg(feature = "redis-store")]
pub mod redis;

#[cfg(feature = "inmemory-store")]
pub mod inmemory;

#[cfg(feature = "postgres-store")]
pub mod postgres;
