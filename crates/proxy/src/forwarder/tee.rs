//! Tee one `ActionEvent` to N sinks.
//!
//! The primary sink (typically `BroadcastingActionStream`) is awaited
//! synchronously so the durable `action_events` row is committed before
//! the request handler returns. Secondary sinks (NATS, SIEM webhook) are
//! awaited concurrently afterwards; each one's failure is logged and
//! metric'd but never propagated — they are append-only audit forwarders,
//! not gating decisions.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::join_all;

use crate::adapters::action_stream::{ActionEvent, ActionStream};

pub struct TeeStream {
    primary: Arc<dyn ActionStream>,
    sinks: Vec<Arc<dyn ActionStream>>,
}

impl TeeStream {
    pub fn new(primary: Arc<dyn ActionStream>) -> Self {
        Self {
            primary,
            sinks: Vec::new(),
        }
    }

    pub fn with_sink(mut self, sink: Arc<dyn ActionStream>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

#[async_trait]
impl ActionStream for TeeStream {
    async fn publish(&self, event: ActionEvent) {
        self.primary.publish(event.clone()).await;
        if self.sinks.is_empty() {
            return;
        }
        let mut futs = Vec::with_capacity(self.sinks.len());
        for sink in &self.sinks {
            let sink = sink.clone();
            let ev = event.clone();
            futs.push(async move { sink.publish(ev).await });
        }
        join_all(futs).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct Collector(Mutex<Vec<ActionEvent>>);

    #[async_trait]
    impl ActionStream for Collector {
        async fn publish(&self, e: ActionEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    fn sample() -> ActionEvent {
        ActionEvent {
            request_id: Uuid::new_v4(),
            agent_session_id: Uuid::new_v4(),
            p_0: "alice@demo.local".into(),
            leaf_pca_id: None,
            vendor: "google".into(),
            action: "drive.files.get".into(),
            method: "GET".into(),
            path: "/drive/v3/files/x".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            at: Utc::now(),
            policy_id: None,
            extra: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn fans_out_to_all_sinks() {
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let s2 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone())
            .with_sink(s1.clone())
            .with_sink(s2.clone());
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(s1.0.lock().unwrap().len(), 1);
        assert_eq!(s2.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_sinks_still_calls_primary() {
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone());
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(tee.sink_count(), 0);
    }
}
