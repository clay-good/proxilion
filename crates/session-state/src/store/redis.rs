///! Redis-based session store
///!
///! Primary storage backend for Docker/self-hosted deployments.
///! Provides fast, scalable session storage with automatic expiration.

use crate::SessionState;
use super::{SessionStore, SessionStoreError, Result};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};

/// Redis session store
pub struct RedisSessionStore {
    client: ConnectionManager,
    ttl_seconds: u64,
}

impl RedisSessionStore {
    /// Create a new Redis session store
    pub async fn new(redis_url: &str) -> Result<Self> {
        Self::with_ttl(redis_url, 86400).await // 24 hours default
    }

    /// Create a new Redis session store with custom TTL
    pub async fn with_ttl(redis_url: &str, ttl_seconds: u64) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| SessionStoreError::ConnectionError(format!("Failed to create Redis client: {}", e)))?;

        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| SessionStoreError::ConnectionError(format!("Failed to connect to Redis: {}", e)))?;

        Ok(Self {
            client: conn,
            ttl_seconds,
        })
    }

    /// Get session key
    fn session_key(&self, session_id: &str) -> String {
        format!("session:{}", session_id)
    }

    /// Get user sessions index key
    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("user:{}:sessions", user_id)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionState>> {
        let key = self.session_key(session_id);
        let mut conn = self.client.clone();

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis GET failed: {}", e)))?;

        match data {
            Some(json) => {
                let session: SessionState = serde_json::from_str(&json)
                    .map_err(|e| SessionStoreError::SerializationError(format!("Failed to deserialize session: {}", e)))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn put_session(&self, session: &SessionState) -> Result<()> {
        let key = self.session_key(&session.session_id);
        let user_key = self.user_sessions_key(&session.user_id);
        let mut conn = self.client.clone();

        // Serialize session
        let json = serde_json::to_string(session)
            .map_err(|e| SessionStoreError::SerializationError(format!("Failed to serialize session: {}", e)))?;

        // Store session with TTL
        conn.set_ex::<_, _, ()>(&key, json, self.ttl_seconds)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis SETEX failed: {}", e)))?;

        // Add session ID to user's session set
        conn.sadd::<_, _, ()>(&user_key, &session.session_id)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis SADD failed: {}", e)))?;

        // Set TTL on user sessions set too
        conn.expire::<_, ()>(&user_key, self.ttl_seconds as i64)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis EXPIRE failed: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let key = self.session_key(session_id);
        let mut conn = self.client.clone();

        // Get session to find user_id
        if let Some(session) = self.get_session(session_id).await? {
            let user_key = self.user_sessions_key(&session.user_id);

            // Remove from user's session set
            let _: () = conn
                .srem(&user_key, session_id)
                .await
                .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis SREM failed: {}", e)))?;
        }

        // Delete session
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis DEL failed: {}", e)))?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<String>> {
        let user_key = self.user_sessions_key(user_id);
        let mut conn = self.client.clone();

        let session_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e: RedisError| SessionStoreError::BackendError(format!("Redis SMEMBERS failed: {}", e)))?;

        Ok(session_ids)
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionState>> {
        let session_ids = self.list_user_sessions(user_id).await?;
        let mut sessions = Vec::new();

        for session_id in session_ids {
            if let Some(session) = self.get_session(&session_id).await? {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> Result<RedisSessionStore> {
        // Use Redis running in Docker for tests
        RedisSessionStore::new("redis://localhost:6379").await
    }

    #[tokio::test]
    #[ignore] // Only run if Redis is available
    async fn test_redis_store() {
        let store = create_test_store().await.unwrap();

        let session = SessionState::new(
            "test_session".to_string(),
            "test_user".to_string(),
            1000000,
        );

        // Put session
        store.put_session(&session).await.unwrap();

        // Get session
        let retrieved = store.get_session("test_session").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, "test_session");

        // List user sessions
        let sessions = store.list_user_sessions("test_user").await.unwrap();
        assert_eq!(sessions.len(), 1);

        // Delete session
        store.delete_session("test_session").await.unwrap();

        // Verify deleted
        let deleted = store.get_session("test_session").await.unwrap();
        assert!(deleted.is_none());
    }
}
