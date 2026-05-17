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
        "actions:purge",
        "delete rows from the audit log older than a cutoff (retention)",
        "POST /api/v1/actions/purge",
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
            assert!(
                !endpoints.is_empty(),
                "scope `{s}` has empty endpoints list"
            );
        }
    }

    #[test]
    fn scope_strings_returns_one_per_catalogue_entry() {
        let strs = scope_strings();
        assert_eq!(strs.len(), SCOPE_CATALOGUE.len());
        // The helper preserves catalogue order — operators rendering the
        // listing should see `*` (admin wildcard) first.
        assert_eq!(strs.first().copied(), Some("*"));
    }

    /// Pin the operator-facing scopes the CLI documents. Adding a new
    /// scope is a wire-contract change — bump this list together with the
    /// docs that reference the scope.
    #[test]
    fn known_scope_set_is_present() {
        let strs: HashSet<&str> = scope_strings().into_iter().collect();
        for required in [
            "*",
            "policy:read",
            "policy:write",
            "blocks:read",
            "blocks:approve",
            "killswitch:revoke",
            "actions:read",
            "actions:export",
            "actions:purge",
            "pca:read",
            "notifier:read",
            "notifier:write",
        ] {
            assert!(strs.contains(required), "missing scope `{required}`");
        }
    }

    #[test]
    fn catalogue_carries_at_least_twelve_entries_per_documented_spec() {
        // The catalogue's length is the operator-facing surface — the
        // CLI's `tokens scopes` rendering keys on it. A regression
        // that accidentally deleted an entry (e.g. during a search-
        // and-replace cleanup) would silently drop a scope from the
        // catalogue while still passing the per-scope substring tests
        // above. Pin a minimum count (currently 12) so a deletion
        // surfaces as a test failure rather than as an operator
        // calling support.
        assert!(
            SCOPE_CATALOGUE.len() >= 12,
            "catalogue shrunk to {} entries — verify intent",
            SCOPE_CATALOGUE.len(),
        );
    }

    #[test]
    fn every_non_wildcard_endpoint_field_mentions_api_v1_route() {
        // Each scope's `endpoints` field is the operator-facing
        // "which routes need this" hint rendered in the CLI. Every
        // non-wildcard entry must mention an `/api/v1/` route (the
        // proxy's only public versioned namespace) so the CLI output
        // reads consistently. The wildcard entry is exempt — it
        // documents "all `/api/v1/*` endpoints" as a class, not a
        // single route.
        for (s, _, endpoints) in SCOPE_CATALOGUE {
            assert!(
                endpoints.contains("/api/v1/"),
                "scope `{s}` endpoints field doesn't mention /api/v1/: {endpoints}",
            );
        }
    }

    #[test]
    fn scope_strings_preserves_catalogue_order_end_to_end() {
        // The helper returns scope strings in catalogue order; the
        // existing test only pins `*` first. Pin the full sequence
        // index-by-index so a refactor that sorted alphabetically (a
        // common "tidy up" mistake) would surface here — the CLI's
        // rendered order matters for operator muscle memory.
        let strs = scope_strings();
        for (i, (cat_scope, _, _)) in SCOPE_CATALOGUE.iter().enumerate() {
            assert_eq!(
                strs[i], *cat_scope,
                "position {i} differs: helper={} catalogue={}",
                strs[i], cat_scope,
            );
        }
    }

    #[test]
    fn every_scope_string_uses_kebab_or_colon_format() {
        // Cosmetic but worth pinning: every operator scope must be
        // either `*` or `<group>:<verb>` so the CLI listing reads
        // consistently. A space or comma would break shell parsing.
        for (s, _, _) in SCOPE_CATALOGUE {
            if *s == "*" {
                continue;
            }
            assert!(
                s.contains(':'),
                "scope `{s}` doesn't follow group:verb shape"
            );
            assert!(
                !s.contains(' ') && !s.contains(','),
                "scope `{s}` contains a shell-unsafe char"
            );
        }
    }
}
