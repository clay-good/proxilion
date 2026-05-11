//! `AdapterState` — everything an adapter handler needs, in one Clone bag.

use std::sync::Arc;

use crate::auth_middleware::AuthState;
use crate::pic::PicExecutor;

use super::action_stream::ActionStream;

#[derive(Clone)]
pub struct AdapterState {
    pub auth: AuthState,
    pub policy: Arc<policy_engine::Engine>,
    pub pic: PicExecutor,
    pub upstream: reqwest::Client,
    pub stream: Arc<dyn ActionStream>,
    /// Override Google's base URL for tests (wiremock). Production passes
    /// `None` and the adapter hard-codes `https://www.googleapis.com`.
    pub google_api_base: Option<String>,
    /// Customer domain — substituted into policy templates (`${customer_domain}`).
    pub customer_domain: String,
}

impl AdapterState {
    pub fn google_api_base(&self) -> &str {
        self.google_api_base
            .as_deref()
            .unwrap_or("https://www.googleapis.com")
    }
}
