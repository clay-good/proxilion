//! Operator-token scope catalogue.
//!
//! Single source of truth. Consumed by:
//! - `proxy::operator_auth` (re-exports `SCOPE_CATALOGUE` + `scope_strings`)
//! - `proxilion-cli tokens scopes` (renders this catalogue)
//! - future SCIM / IdP-group sync
//!
//! Each entry is `(scope, description, endpoints)`. Endpoints is a short
//! human-readable list of routes that require the scope; kept in sync by
//! code review.

pub const SCOPE_CATALOGUE: &[(&str, &str, &str)] = &[
    (
        "*",
        "wildcard — accepts every scope check; bootstrap admin only",
        "all `/api/v1/*` endpoints",
    ),
    (
        "policy:read",
        "read policy bundle + per-policy mode",
        "GET /api/v1/policy",
    ),
    (
        "policy:write",
        "force-reload policy from source; flip a single policy's mode",
        "POST /api/v1/policy/reload, POST /api/v1/policy/{id}/mode",
    ),
    (
        "blocks:read",
        "list + inspect blocked-action queue",
        "GET /api/v1/blocked, GET /api/v1/blocked/{id}",
    ),
    (
        "blocks:approve",
        "approve / reject blocked actions; issue email signed-URL links",
        "POST /api/v1/blocked/{id}/{approve,reject,issue-link}",
    ),
    (
        "killswitch:revoke",
        "revoke bearer(s) for a session, user, or globally",
        "POST /api/v1/killswitch/{session,user,all}/...",
    ),
    (
        "actions:read",
        "read audit log (history, SSE, single record)",
        "GET /api/v1/actions, .../stream, .../{id}, /api/v1/sessions/{id}/chain",
    ),
    (
        "actions:export",
        "bulk audit export (NDJSON / CSV streamed from a postgres cursor)",
        "GET /api/v1/actions/export",
    ),
    (
        "pca:read",
        "fetch + verify PCAs",
        "GET /api/v1/pca/{id}, GET /api/v1/pca/{id}/verify",
    ),
    (
        "notifier:read",
        "inspect notifier driver configuration (URLs / secrets redacted)",
        "GET /api/v1/notifier/config, /show",
    ),
    (
        "notifier:write",
        "configure / hot-swap a notifier driver",
        "POST /api/v1/notifier/config, /test",
    ),
];

pub fn scope_strings() -> Vec<&'static str> {
    SCOPE_CATALOGUE.iter().map(|(s, _, _)| *s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_scopes() {
        let mut seen = HashSet::new();
        for (s, _, _) in SCOPE_CATALOGUE {
            assert!(seen.insert(*s), "duplicate scope `{s}` in catalogue");
        }
    }

    #[test]
    fn wildcard_is_present() {
        assert!(SCOPE_CATALOGUE.iter().any(|(s, _, _)| *s == "*"));
    }

    #[test]
    fn descriptions_are_non_empty() {
        for (s, desc, endpoints) in SCOPE_CATALOGUE {
            assert!(!desc.is_empty(), "scope `{s}` has empty description");
            assert!(!endpoints.is_empty(), "scope `{s}` has empty endpoints list");
        }
    }
}
