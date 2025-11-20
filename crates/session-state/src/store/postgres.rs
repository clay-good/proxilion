///! PostgreSQL-based session store
///!
///! Enterprise-grade storage backend with full ACID compliance.
///! Provides durable session storage with relational query capabilities.

use crate::SessionState;
use super::{SessionStore, SessionStoreError, Result};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use sqlx::postgres::PgPoolOptions;

/// PostgreSQL session store
pub struct PostgresSessionStore {
    pool: PgPool,
}

impl PostgresSessionStore {
    /// Create a new PostgreSQL session store
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| SessionStoreError::ConnectionError(format!("Failed to connect to PostgreSQL: {}", e)))?;

        // Ensure tables exist
        Self::init_schema(&pool).await?;

        Ok(Self { pool })
    }

    /// Initialize database schema
    async fn init_schema(pool: &PgPool) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                data JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("Failed to create sessions table: {}", e)))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("Failed to create index: {}", e)))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at)
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("Failed to create index: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionState>> {
        let row = sqlx::query(
            r#"
            SELECT data FROM sessions WHERE session_id = $1
            "#
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("PostgreSQL SELECT failed: {}", e)))?;

        match row {
            Some(row) => {
                let json_value: serde_json::Value = row.try_get("data")
                    .map_err(|e| SessionStoreError::SerializationError(format!("Failed to get data column: {}", e)))?;

                let session: SessionState = serde_json::from_value(json_value)
                    .map_err(|e| SessionStoreError::SerializationError(format!("Failed to deserialize session: {}", e)))?;

                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn put_session(&self, session: &SessionState) -> Result<()> {
        let json_value = serde_json::to_value(session)
            .map_err(|e| SessionStoreError::SerializationError(format!("Failed to serialize session: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO sessions (session_id, user_id, data, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (session_id)
            DO UPDATE SET data = $3, updated_at = NOW()
            "#
        )
        .bind(&session.session_id)
        .bind(&session.user_id)
        .bind(&json_value)
        .execute(&self.pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("PostgreSQL INSERT/UPDATE failed: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM sessions WHERE session_id = $1
            "#
        )
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("PostgreSQL DELETE failed: {}", e)))?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT session_id FROM sessions WHERE user_id = $1 ORDER BY updated_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("PostgreSQL SELECT failed: {}", e)))?;

        let session_ids: Vec<String> = rows.iter()
            .map(|row| row.try_get("session_id"))
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(|e| SessionStoreError::SerializationError(format!("Failed to get session_id: {}", e)))?;

        Ok(session_ids)
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionState>> {
        let rows = sqlx::query(
            r#"
            SELECT data FROM sessions WHERE user_id = $1 ORDER BY updated_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SessionStoreError::BackendError(format!("PostgreSQL SELECT failed: {}", e)))?;

        let mut sessions = Vec::new();
        for row in rows {
            let json_value: serde_json::Value = row.try_get("data")
                .map_err(|e| SessionStoreError::SerializationError(format!("Failed to get data column: {}", e)))?;

            let session: SessionState = serde_json::from_value(json_value)
                .map_err(|e| SessionStoreError::SerializationError(format!("Failed to deserialize session: {}", e)))?;

            sessions.push(session);
        }

        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> Result<PostgresSessionStore> {
        // Use PostgreSQL running in Docker for tests
        PostgresSessionStore::new("postgresql://postgres:postgres@localhost:5432/proxilion_test").await
    }

    #[tokio::test]
    #[ignore] // Only run if PostgreSQL is available
    async fn test_postgres_store() {
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

        // Get all user sessions
        let user_sessions = store.get_user_sessions("test_user").await.unwrap();
        assert_eq!(user_sessions.len(), 1);

        // Delete session
        store.delete_session("test_session").await.unwrap();

        // Verify deleted
        let deleted = store.get_session("test_session").await.unwrap();
        assert!(deleted.is_none());

        // Verify user session list is empty
        let sessions_after_delete = store.list_user_sessions("test_user").await.unwrap();
        assert_eq!(sessions_after_delete.len(), 0);
    }

    #[tokio::test]
    #[ignore] // Only run if PostgreSQL is available
    async fn test_multiple_sessions() {
        let store = create_test_store().await.unwrap();

        // Create 3 sessions for same user
        for i in 0..3 {
            let session = SessionState::new(
                format!("session_{}", i),
                "test_user".to_string(),
                1000000 + i as i64,
            );
            store.put_session(&session).await.unwrap();
        }

        // List should return 3 sessions
        let sessions = store.list_user_sessions("test_user").await.unwrap();
        assert_eq!(sessions.len(), 3);

        // Get all sessions
        let user_sessions = store.get_user_sessions("test_user").await.unwrap();
        assert_eq!(user_sessions.len(), 3);

        // Delete one
        store.delete_session("session_1").await.unwrap();

        // Should have 2 left
        let sessions_after = store.list_user_sessions("test_user").await.unwrap();
        assert_eq!(sessions_after.len(), 2);
    }

    #[tokio::test]
    #[ignore] // Only run if PostgreSQL is available
    async fn test_upsert() {
        let store = create_test_store().await.unwrap();

        let mut session = SessionState::new(
            "upsert_test".to_string(),
            "test_user".to_string(),
            1000000,
        );

        // Insert
        store.put_session(&session).await.unwrap();

        // Update
        session.total_requests += 10;
        store.put_session(&session).await.unwrap();

        // Verify update
        let retrieved = store.get_session("upsert_test").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().total_requests, 10);

        // Clean up
        store.delete_session("upsert_test").await.unwrap();
    }
}
