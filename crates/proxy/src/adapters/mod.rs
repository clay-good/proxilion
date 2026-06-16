//! SaaS adapters. Each adapter owns its routes; all share `AdapterState`,
//! `AppError`, and the read-filter + action-stream helpers.

pub mod action_stream;
pub mod error;
pub mod google_calendar;
pub mod google_drive;
pub mod google_gmail;
pub mod policy_trace;
pub mod read_filter;
pub mod state;

#[allow(unused_imports)]
pub use action_stream::{ActionEvent, ActionStream, LoggingStream};
#[allow(unused_imports)]
pub use error::AppError;
pub use state::AdapterState;

/// Percent-encode a single attacker-controlled path id before it is
/// interpolated into an upstream URL.
///
/// Authority: surface-delight-and-correctness.md §6.1. axum percent-decodes
/// `{id}` path params before the handler sees them, so a raw `format!` of the
/// decoded id lets `/`, `?`, `#`, `&`, `%` re-inject path/query/fragment
/// delimiters and steer the upstream call to a *different* Google endpoint
/// than the action label, policy layer, and PIC chain were evaluated against
/// (a confused-deputy vector). Encoding each id segment keeps the upstream
/// path byte-for-byte the resource the request was authorized for.
///
/// The reserved set mirrors the Calendar adapter's original local encoder:
/// controls + ` ` `/` `?` `#` `&` `%`. `@` and `.` pass through verbatim so
/// email-shaped ids (`alice@org.com`) and `me` survive unchanged.
pub(crate) fn path_segment(s: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    const PATH: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'/')
        .add(b'?')
        .add(b'#')
        .add(b'&')
        .add(b'%');
    utf8_percent_encode(s, PATH).to_string()
}

/// `path_segment` with the §7 `proxilion_adapter_path_encoded_total{vendor}`
/// counter incremented once per call — the production entry point every
/// adapter routes its interpolated ids through.
///
/// Authority: surface-delight-and-correctness.md §7 ("Confidence the encode
/// path is exercised in prod"). The pure `path_segment` stays metric-free so
/// the encoding unit tests assert output without a recorder; this thin
/// wrapper carries the observability so the §6.1 fix is provably hot in
/// production rather than only proven in tests.
pub(crate) fn encoded_segment(vendor: &'static str, s: &str) -> String {
    metrics::counter!("proxilion_adapter_path_encoded_total", "vendor" => vendor).increment(1);
    path_segment(s)
}

/// Whether a Layer-B denial should be persisted to `blocked_actions` and
/// fan out to the notifier, shared by every Google adapter's `proxy_request`.
///
/// Both `PolicyBlocked` (a hard deny) and `RequireConfirmation` (a
/// human-in-the-loop gate) enqueue a pending review row — the latter is the
/// *whole point* of the confirmation queue, since an operator must be able to
/// approve it. Every other `AppError` (upstream/transport/PIC/internal) is not
/// a Layer-B policy outcome and is returned to the agent without a queue row.
///
/// This predicate exists so the three adapters can't drift: a previous version
/// inlined the `matches!` guard in each `proxy_request`, and the Drive copy was
/// never widened to include `RequireConfirmation` — so a `require_confirmation`
/// policy on a Drive read denied the agent correctly but wrote no reviewable
/// row and fired no notification, while the identical rule on Gmail/Calendar
/// did. Routing all three through one function makes that divergence
/// impossible.
pub(crate) fn persists_blocked_action(e: &AppError) -> bool {
    matches!(
        e,
        AppError::PolicyBlocked { .. } | AppError::RequireConfirmation(_)
    )
}

/// Read an upstream response body into memory under a hard `max`-byte cap,
/// shared by every Google adapter.
///
/// Authority: spec.md §1.4 ("Buffer responses with a 10MB cap; reject
/// larger"). The cap is a *true* memory bound: we reject early on the
/// advertised `Content-Length` (cheap, before reading a byte), then
/// accumulate the body chunk-by-chunk and abort the instant the running
/// total would exceed `max`. An upstream that omits `Content-Length` and
/// streams past the cap (chunked transfer, or simply lying) is therefore cut
/// off at `max` bytes rather than fully buffered into memory first — which a
/// `resp.bytes().await` followed by a length check would not prevent.
pub(crate) async fn read_bounded(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, AppError> {
    if let Some(len) = resp.content_length() {
        if len as usize > max {
            return Err(AppError::UpstreamTooLarge);
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        // `buf.len() <= max` is the loop invariant, so `max - buf.len()` can't
        // underflow; comparing against the remaining headroom also avoids any
        // `buf.len() + chunk.len()` overflow on a pathological chunk size.
        if chunk.len() > max - buf.len() {
            return Err(AppError::UpstreamTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::path_segment;

    #[test]
    fn path_segment_escapes_path_query_and_fragment_delimiters() {
        // The confused-deputy vectors from §6.1: a decoded id carrying `/`,
        // `?`, `#`, `&`, `%` must not survive into the upstream path verbatim.
        assert_eq!(path_segment("a/b?x"), "a%2Fb%3Fx");
        assert_eq!(path_segment("..%2F..%2Foauth2"), "..%252F..%252Foauth2");
        assert_eq!(path_segment("a#frag"), "a%23frag");
        assert_eq!(path_segment("a&b=c"), "a%26b=c");
    }

    #[test]
    fn path_segment_passes_email_and_resource_shaped_ids_through_verbatim() {
        // Real Gmail/Drive ids and `me` must round-trip unchanged so the
        // encoding is invisible on the happy path.
        assert_eq!(path_segment("1a2b3c4d5e"), "1a2b3c4d5e");
        assert_eq!(path_segment("alice@org.com"), "alice@org.com");
        assert_eq!(path_segment("me"), "me");
    }

    use super::{AppError, persists_blocked_action, read_bounded};
    use bytes::Bytes;

    #[test]
    fn persists_blocked_action_covers_both_layer_b_denials_and_nothing_else() {
        // The two Layer-B outcomes that must enqueue a reviewable
        // `blocked_actions` row + fire the notifier. `RequireConfirmation` is
        // the regression guard: the Drive adapter's inlined `matches!` once
        // omitted it, so a `require_confirmation` policy on a Drive read denied
        // the agent but left no row for an operator to approve.
        assert!(persists_blocked_action(&AppError::PolicyBlocked {
            policy_id: Some("p".into()),
            reason: "blocked".into(),
            override_allowed: true,
        }));
        assert!(persists_blocked_action(&AppError::RequireConfirmation(
            "external recipient".into()
        )));

        // Every non-Layer-B error is returned to the agent without a queue row.
        assert!(!persists_blocked_action(&AppError::RateLimit));
        assert!(!persists_blocked_action(&AppError::PicInvariantViolation(
            "ops not subset".into()
        )));
        assert!(!persists_blocked_action(&AppError::UpstreamTooLarge));
        assert!(!persists_blocked_action(&AppError::ReadFilterBlocked));
        assert!(!persists_blocked_action(&AppError::Internal("boom".into())));
    }

    /// Build a `reqwest::Response` whose body is an unsized stream — so it
    /// carries **no** `Content-Length` and `read_bounded` is forced down the
    /// chunk-accumulation path (the branch the spec.md §1.4 streaming cap
    /// protects) rather than the cheap header pre-check. The body is split into
    /// several small chunks so the running-total comparison is exercised
    /// across multiple loop iterations.
    fn streaming_resp(body: Vec<u8>) -> reqwest::Response {
        let chunks: Vec<Result<Bytes, std::io::Error>> = body
            .chunks(8)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let stream = futures_util::stream::iter(chunks);
        let http_resp = http::Response::builder()
            .status(200)
            .body(reqwest::Body::wrap_stream(stream))
            .unwrap();
        reqwest::Response::from(http_resp)
    }

    #[tokio::test]
    async fn read_bounded_streams_body_under_cap_through_unchanged() {
        let resp = streaming_resp(b"hello world".to_vec());
        // Precondition: no Content-Length, so the streaming loop is what runs.
        assert!(
            resp.content_length().is_none(),
            "test must exercise the chunk-accumulation path, not the header pre-check",
        );
        let out = read_bounded(resp, 10 * 1024).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn read_bounded_rejects_oversized_body_with_no_content_length() {
        // §1.4 — the regression this guards: an upstream that omits
        // `Content-Length` and streams past the cap must be cut off, not
        // buffered whole. 100 bytes against a 10-byte cap → UpstreamTooLarge,
        // and the loop aborts as soon as the running total crosses the cap.
        let resp = streaming_resp(vec![b'x'; 100]);
        assert!(resp.content_length().is_none());
        let r = read_bounded(resp, 10).await;
        assert!(
            matches!(r, Err(AppError::UpstreamTooLarge)),
            "oversized no-Content-Length body must be rejected",
        );
    }

    #[tokio::test]
    async fn read_bounded_accepts_body_exactly_at_cap() {
        // Boundary: a body whose length equals the cap is allowed (the loop
        // rejects only when a chunk would push the total *over* `max`). 64
        // bytes in 8-byte chunks against a 64-byte cap → the final chunk lands
        // exactly on the boundary.
        let resp = streaming_resp(vec![b'y'; 64]);
        let out = read_bounded(resp, 64).await.unwrap();
        assert_eq!(out.len(), 64);
    }

    /// Build a `reqwest::Response` from a **sized** body, so reqwest derives a
    /// `Content-Length` header. This exercises the cheap header pre-check branch
    /// — the complement of `streaming_resp`, which deliberately omits it.
    fn sized_resp(body: Vec<u8>) -> reqwest::Response {
        let http_resp = http::Response::builder()
            .status(200)
            .body(reqwest::Body::from(body))
            .unwrap();
        reqwest::Response::from(http_resp)
    }

    #[tokio::test]
    async fn read_bounded_rejects_on_oversized_content_length_before_reading_body() {
        // The cheap pre-check: a body whose advertised `Content-Length` already
        // exceeds the cap is rejected outright, before the chunk loop reads a
        // single byte. 100 advertised bytes against a 10-byte cap →
        // UpstreamTooLarge. (The streaming tests above force Content-Length to
        // be absent; this is the sibling branch they can't reach.)
        let resp = sized_resp(vec![b'z'; 100]);
        assert_eq!(
            resp.content_length(),
            Some(100),
            "precondition: this response advertises a Content-Length",
        );
        let r = read_bounded(resp, 10).await;
        assert!(
            matches!(r, Err(AppError::UpstreamTooLarge)),
            "oversized Content-Length must reject at the header pre-check",
        );
    }

    #[tokio::test]
    async fn read_bounded_with_content_length_within_cap_returns_full_body() {
        // Complement: an advertised length under the cap passes the pre-check
        // and the body is returned intact — proving the early reject doesn't
        // false-positive on legitimately-sized responses.
        let resp = sized_resp(b"ok".to_vec());
        assert_eq!(resp.content_length(), Some(2));
        let out = read_bounded(resp, 1024).await.unwrap();
        assert_eq!(out, b"ok");
    }

    #[test]
    fn read_bounded_signature_is_response_usize_to_result_vec_u8_apperror() {
        // Pin the shared helper's signature so a refactor that widened the
        // error to `anyhow::Error` (losing the structured `UpstreamTooLarge`
        // variant the operator dashboard's size-cap panel keys on) or changed
        // the owned `Vec<u8>` return (which every adapter moves across the
        // `.await` into the read-filter + audit pipeline) surfaces here rather
        // than at the three call sites. The generic bound names the exact arg
        // and `Output` types without having to name the opaque future.
        fn assert_sig<F, Fut>(_: F)
        where
            F: Fn(reqwest::Response, usize) -> Fut,
            Fut: std::future::Future<Output = Result<Vec<u8>, AppError>>,
        {
        }
        assert_sig(read_bounded);
    }
}
