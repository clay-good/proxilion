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
}
