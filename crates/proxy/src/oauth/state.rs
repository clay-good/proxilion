//! OAuth handler state — DB pool + Google client config + executor handle.
//!
//! Lives separate from the wider proxy AppState so the OAuth handlers can
//! be unit-tested with a mocked-up state.

use std::sync::Arc;

use sqlx::PgPool;

use crate::crypto::TokenCipher;
use crate::pic::PicExecutor;

#[derive(Clone)]
pub struct OAuthState {
    pub db: PgPool,
    pub cipher: Arc<TokenCipher>,
    pub pic: PicExecutor,
    pub google: GoogleClient,
    /// Federation-bridge user-authorize endpoint (full URL).
    pub federation_bridge_authorize_url: String,
    /// Proxy's own public base URL — used to build redirect_uris we hand
    /// to upstream OAuth servers.
    pub proxy_base_url: String,
}

#[derive(Clone, Debug)]
pub struct GoogleClient {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String, // default: https://accounts.google.com/o/oauth2/v2/auth
    pub token_url: String, // default: https://oauth2.googleapis.com/token
}

impl GoogleClient {
    #[allow(dead_code)] // convenience constructor; server.rs builds the struct inline
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            client_id: std::env::var("GOOGLE_CLIENT_ID")
                .map_err(|_| "GOOGLE_CLIENT_ID is required".to_string())?,
            client_secret: std::env::var("GOOGLE_CLIENT_SECRET")
                .map_err(|_| "GOOGLE_CLIENT_SECRET is required".to_string())?,
            auth_url: std::env::var("GOOGLE_AUTH_URL")
                .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".into()),
            token_url: std::env::var("GOOGLE_TOKEN_URL")
                .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
        })
    }
}
