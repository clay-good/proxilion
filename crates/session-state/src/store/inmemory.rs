///! In-memory session store
///!
///! Fast, ephemeral session storage for testing and demo mode.
///! All data is lost when the process stops.

use crate::SessionState;
use super::{SessionStore, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory session store
#[derive(Clone)]
pub struct InMemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionState>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn put_session(&self, session: &SessionState) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        // Store session
        sessions.insert(session.session_id.clone(), session.clone());

        // Add to user's session list
        user_sessions
            .entry(session.user_id.clone())
            .or_insert_with(Vec::new)
            .push(session.session_id.clone());

        Ok(())
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        // Get session to find user_id
        if let Some(session) = sessions.remove(session_id) {
            // Remove from user's session list
            if let Some(user_session_list) = user_sessions.get_mut(&session.user_id) {
                user_session_list.retain(|id| id != session_id);

                // Remove empty user session lists
                if user_session_list.is_empty() {
                    user_sessions.remove(&session.user_id);
                }
            }
        }

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<String>> {
        let user_sessions = self.user_sessions.read().await;
        Ok(user_sessions
            .get(user_id)
            .map(|sessions| sessions.clone())
            .unwrap_or_default())
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionState>> {
        let session_ids = self.list_user_sessions(user_id).await?;
        let sessions_lock = self.sessions.read().await;

        let mut sessions = Vec::new();
        for session_id in session_ids {
            if let Some(session) = sessions_lock.get(&session_id) {
                sessions.push(session.clone());
            }
        }

        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inmemory_store() {
        let store = InMemorySessionStore::new();

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
    async fn test_multiple_sessions() {
        let store = InMemorySessionStore::new();

        // Create 3 sessions for same user
        for i in 0..3 {
            let session = SessionState::new(
                format!("session_{}", i),
                "test_user".to_string(),
                1000000 + i,
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
}
