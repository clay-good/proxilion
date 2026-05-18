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

    #[test]
    fn sanitize_preserves_hyphens_underscores_and_alphanum() {
        // Hyphen + underscore are valid in NATS subjects and must pass
        // through. Vendor / action enums sometimes carry them (e.g. a
        // future `gmail-beta` vendor label) — silently `_`-replacing them
        // would split wildcard subscriptions.
        assert_eq!(sanitize_token("gmail-beta_v2.0"), "gmail-beta_v2.0");
        assert_eq!(sanitize_token("ABCdef123"), "ABCdef123");
    }

    #[test]
    fn sanitize_empty_returns_empty() {
        assert!(sanitize_token("").is_empty());
    }

    #[test]
    fn sanitize_replaces_unicode_with_underscore() {
        // Non-ASCII chars are not part of the allowed subject alphabet.
        // The classifier collapses them all to `_` so multibyte input
        // never breaks subject parsing on the subscriber side.
        let s = sanitize_token("café→x");
        assert!(s.starts_with("ca"));
        assert!(s.ends_with("x"));
        assert!(s.contains('_'));
    }

    #[test]
    fn connect_error_display_contains_reason() {
        let e = ConnectError("connection refused".into());
        let s = format!("{e}");
        assert!(s.contains("connection refused"));
        assert!(s.contains("nats connect failed"));
    }

    #[test]
    fn sanitize_replaces_whitespace_tab_and_newline_with_underscore() {
        // NATS subject parser splits on ASCII whitespace; an unsanitized
        // tab or newline would silently fork the subject into two tokens
        // and break wildcard subscriptions. Pin each whitespace variant
        // — a refactor that hardcoded only `' '` would let `\t` / `\n`
        // through to the wire.
        assert_eq!(sanitize_token("a b"), "a_b");
        assert_eq!(sanitize_token("a\tb"), "a_b");
        assert_eq!(sanitize_token("a\nb"), "a_b");
        assert_eq!(sanitize_token("a\rb"), "a_b");
    }

    #[test]
    fn sanitize_replaces_nats_wildcard_chars_star_and_gt() {
        // `*` and `>` are NATS subject wildcards — a vendor / action
        // string accidentally carrying them would let an attacker craft
        // a publish that overlaps a subscription it shouldn't (e.g. an
        // adversarial filename of `*` matching `actions.google.*`).
        // Pin both replacements explicitly so the regex hardening can
        // never silently regress.
        assert_eq!(sanitize_token("*"), "_");
        assert_eq!(sanitize_token(">"), "_");
        assert_eq!(sanitize_token("a*b>c"), "a_b_c");
    }

    #[test]
    fn sanitize_dot_passthrough_preserves_subject_hierarchy() {
        // `.` is the NATS subject separator. The sanitizer MUST let it
        // through so a multi-token vendor like `drive.files.get` lands
        // as the three-token subject suffix the spec.md §3.1 wildcard
        // examples expect (`actions.google.drive.files.>`). A refactor
        // that filtered `.` would collapse every multi-token action
        // into a single token and silently break wildcards.
        assert_eq!(sanitize_token("a.b.c"), "a.b.c");
        assert_eq!(sanitize_token(".leading"), ".leading");
        assert_eq!(sanitize_token("trailing."), "trailing.");
    }

    #[test]
    fn sanitize_token_replaces_ascii_control_chars_with_underscore() {
        // The classifier accepts `a-zA-Z0-9.-_` and replaces every other
        // character with `_`. The control-char range (0x00–0x1F) is the
        // most operationally-load-bearing axis: a raw NUL or VT character
        // smuggled into a vendor or action label (via a future adapter
        // that doesn't sanitize its inputs at the policy-engine layer
        // first) would otherwise land on the NATS wire as a subject
        // token, and most NATS clients reject the whole publish on a
        // control char. Pin the entire 0x00..=0x1F range via a sweep —
        // a refactor that narrowed the closure's reject set to a hand-
        // rolled `matches!(c, ' ' | '\t' | '\n')` (the round-30 test's
        // partial whitespace pin) would silently let DEL, VT, FF, etc.
        // through. The existing whitespace test pins `\t`/`\n`/`\r`/`' '`
        // by example; this fills in the rest of the range.
        for code in 0u8..=0x1f {
            let s = format!("a{}b", code as char);
            let out = sanitize_token(&s);
            assert_eq!(
                out, "a_b",
                "control char {code:#04x} must sanitize to underscore, got {out:?}",
            );
        }
    }

    #[test]
    fn sanitize_token_replaces_punctuation_with_underscore_per_allow_list() {
        // The allow-list closure is `'a'..='z' | 'A'..='Z' | '0'..='9' |
        // '.' | '-' | '_'`. Pin the explicit reject path for every
        // ASCII punctuation char NOT on the list — a refactor that
        // widened the allow-list to "any printable ASCII" (a tempting
        // "be lenient on inputs" change) would silently start landing
        // quote chars, parentheses, and shell metacharacters on the
        // NATS subject wire. Pin a representative spread.
        for ch in [
            '"', '\'', '`', '(', ')', '[', ']', '{', '}', '/', '\\', ';', ':', '<', '>', '?', '@',
            '#', '$', '%', '^', '&', '!', '|', '~', '=', '+',
        ] {
            let s = format!("a{ch}b");
            let out = sanitize_token(&s);
            assert_eq!(
                out, "a_b",
                "punctuation {ch:?} must sanitize to underscore, got {out:?}",
            );
        }
    }

    #[test]
    fn sanitize_token_preserves_all_ten_decimal_digits_independently() {
        // `'0'..='9'` is on the allow-list — pin EACH digit independently
        // (not just 0..=9 as a range walk, which would mask a regression
        // that hand-rolled the range as `'1'..='9'` and dropped zero,
        // for some "leading-zero-rejection" cleanup). Operators use
        // versioned vendor names (`drive_v1`, `gmail_v2`); a regression
        // that dropped any digit would silently corrupt those subjects.
        for d in '0'..='9' {
            let s = format!("v{d}x");
            let out = sanitize_token(&s);
            assert_eq!(out, format!("v{d}x"), "digit {d} must pass through");
        }
    }

    #[test]
    fn sanitize_token_byte_length_equals_input_for_ascii_only_inputs() {
        // The sanitizer is a per-`char` map — for any ASCII-only input,
        // the output byte length must equal the input byte length
        // exactly (every input char maps to either itself or `_`, both
        // 1 byte). Pin the invariant on a spread of inputs the adapters
        // emit (vendor/action labels, kebab forms, dotted hierarchies)
        // — a refactor that started escaping rejected chars with a
        // multi-byte sequence (e.g. percent-encoding `%2A` for `*`)
        // would silently inflate subject lengths and break the
        // wildcard subscription depth contract.
        for input in [
            "google",
            "drive.files.get",
            "gmail-beta_v2.0",
            "*invalid*",
            "a b c",
            "punctuation!?@#",
        ] {
            let out = sanitize_token(input);
            assert_eq!(
                out.len(),
                input.len(),
                "ASCII input {input:?} → {out:?}: byte length must be preserved",
            );
        }
    }

    #[test]
    fn connect_error_implements_std_error_trait_for_anyhow_chain_walking() {
        // The boot path bubbles `ConnectError` through `anyhow::Error`
        // chains for structured logging — pin that the `thiserror`
        // derive lands the `std::error::Error` impl so a refactor
        // that swapped to a hand-rolled error type (dropping the
        // derive) would surface here at the trait-object cast rather
        // than at the call-site type mismatch in `server.rs`. The
        // leaf-arm `source()` is None since the inner is a bare String,
        // not a wrapped error — pin that contract too so a future
        // refactor to `ConnectError(#[source] reqwest::Error)` "for
        // anyhow-style chain walking" would be a deliberate wire-shape
        // change.
        let e = ConnectError("dns failure".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("dns failure"));
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "leaf-arm ConnectError must not expose a source",
        );
    }

    #[test]
    fn connect_error_inner_field_is_pub_and_round_trips_through_construction() {
        // `pub struct ConnectError(pub String)` — the tuple field is
        // `pub` so the boot path can introspect the inner reason
        // without parsing the Display string (operator setup-status
        // dashboards split on the inner message to surface a
        // category-specific hint). Pin both that the field is
        // accessible AND that construction preserves the value
        // byte-identically (no normalization snuck into the
        // constructor). A refactor that made the field private would
        // surface as a compile error; one that normalized the inner
        // (e.g. trimmed whitespace "for tidiness") would surface here.
        let e = ConnectError("  preserved with leading spaces  ".to_string());
        assert_eq!(e.0, "  preserved with leading spaces  ");
        // Three distinct messages each round-trip through the public
        // field accessor — a refactor that started interning or
        // normalizing would surface across the walk.
        for msg in ["", "connection refused", "тест unicode"] {
            let e = ConnectError(msg.into());
            assert_eq!(e.0, msg);
        }
    }

    #[test]
    fn connect_error_debug_includes_struct_name_for_grep() {
        // The `#[derive(Debug)]` on `ConnectError` feeds `?e` in
        // `tracing::warn!(?e, "nats connect failed")` at the boot path
        // — pin that the struct name AND the wrapped reason both
        // appear so an operator grep for `ConnectError` lands the
        // log line.
        let e = ConnectError("dns failure".into());
        let s = format!("{e:?}");
        assert!(s.contains("ConnectError"), "got: {s}");
        assert!(s.contains("dns failure"));
    }
}
