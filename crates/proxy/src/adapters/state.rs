//! `AdapterState` — everything an adapter handler needs, in one Clone bag.

use std::sync::Arc;

use crate::auth_middleware::AuthState;
use crate::notifier::Notifiers;
use crate::pic::PicExecutor;
use crate::policy_handle::PolicyHandle;

use super::action_stream::ActionStream;

#[derive(Clone)]
pub struct AdapterState {
    pub auth: AuthState,
    /// Hot-reloadable handle. Adapters call `policy.load()` once per
    /// request to snapshot the current engine.
    pub policy: PolicyHandle,
    pub pic: PicExecutor,
    pub upstream: reqwest::Client,
    pub stream: Arc<dyn ActionStream>,
    /// Override Google's base URL for tests (wiremock). Production passes
    /// `None` and the adapter hard-codes `https://www.googleapis.com`.
    pub google_api_base: Option<String>,
    /// Customer domain — substituted into policy templates (`${customer_domain}`).
    pub customer_domain: String,
    /// All notifier drivers bundled. Each is independently hot-swappable
    /// via `/api/v1/notifier/config`; absent drivers no-op at fan-out.
    pub notifier: Notifiers,
}

impl AdapterState {
    pub fn google_api_base(&self) -> &str {
        self.google_api_base
            .as_deref()
            .unwrap_or("https://www.googleapis.com")
    }
}
