//! NATS JetStream action-event bridge (spec.md §3.1).
//!
//! Subject layout: `actions.<vendor>.<action>` (e.g.
//! `actions.google.drive.files.get`). Vendor and action are
//! already-bounded enums in the adapter layer, so the subject space is
//! safely finite and a customer can subscribe with wildcards
//! (`actions.>`, `actions.google.>`, `actions.*.gmail.messages.send`).
//!
//! We publish *plain* NATS (not JetStream) because the durable record is
//! the `action_events` table — NATS is the live fan-out. If the customer
//! wants a durable replayable stream, configuring JetStream to ingest the
//! `actions.>` subject is a server-side concern, not ours. Keeps the
//! proxy stateless w.r.t. NATS.

use async_trait::async_trait;
use bytes::Bytes;
use tracing::warn;

use crate::adapters::action_stream::{ActionEvent, ActionStream};

pub struct NatsBridge {
    client: async_nats::Client,
    /// Subject prefix — defaults to "actions". Configurable so customers
    /// can route different proxy deployments to the same NATS account
    /// without subject collisions.
    prefix: String,
}

impl NatsBridge {
    pub async fn connect(url: &str, prefix: impl Into<String>) -> Result<Self, ConnectError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ConnectError(e.to_string()))?;
        Ok(Self {
            client,
            prefix: prefix.into(),
        })
    }

    fn subject_for(&self, event: &ActionEvent) -> String {
        // Sanitize: NATS subjects can't contain spaces, `*`, `>`, `.` (we
        // already split on `.`). The vendor/action enums in the adapter
        // produce alphanum + `.`, so we just need to swap any other char
        // for `_` defensively.
        let action = sanitize_token(&event.action);
        let vendor = sanitize_token(&event.vendor);
        format!("{}.{}.{}", self.prefix, vendor, action)
    }
}

fn sanitize_token(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
#[error("nats connect failed: {0}")]
pub struct ConnectError(pub String);

#[async_trait]
impl ActionStream for NatsBridge {
    async fn publish(&self, event: ActionEvent) {
        let subject = self.subject_for(&event);
        let payload = match serde_json::to_vec(&event) {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                warn!(error = %e, "nats: serialize ActionEvent failed");
                metrics::counter!(
                    "proxilion_nats_publish_failures_total",
                    "reason" => "serialize"
                )
                .increment(1);
                return;
            }
        };
        match self.client.publish(subject.clone(), payload).await {
            Ok(()) => {
                metrics::counter!(
                    "proxilion_nats_publish_total",
                    "decision" => event.decision.clone()
                )
                .increment(1);
            }
            Err(e) => {
                warn!(error = %e, subject = %subject, "nats: publish failed");
                metrics::counter!(
                    "proxilion_nats_publish_failures_total",
                    "reason" => "publish"
                )
                .increment(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_includes_vendor_and_action() {
        // Stand up a NatsBridge with a dummy client is awkward; we test
        // the subject computation on a pseudo-instance by reconstructing
        // the formatter inline. The shape is what's load-bearing for
        // wildcard subscribers.
        let event_action = "drive.files.get";
        let event_vendor = "google";
        let subj = format!(
            "{}.{}.{}",
            "actions",
            sanitize_token(event_vendor),
            sanitize_token(event_action)
        );
        assert_eq!(subj, "actions.google.drive.files.get");
    }

    #[test]
    fn sanitize_replaces_invalid_chars() {
        assert_eq!(sanitize_token("a*b>c d"), "a_b_c_d");
        assert_eq!(sanitize_token("drive.files.get"), "drive.files.get");
    }
}
