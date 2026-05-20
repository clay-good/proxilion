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

    #[test]
    fn scope_catalogue_entries_all_use_static_str_lifetime_for_zero_alloc_cli_render() {
        // The CLI renders `tokens scopes` by iterating SCOPE_CATALOGUE
        // and printing each tuple's scope + description + endpoints.
        // All three field types MUST be `&'static str` so the catalogue
        // can be stored in `.rodata` and read across an unbounded number
        // of CLI invocations without allocation. A refactor that lifted
        // the catalogue to runtime construction (e.g. for i18n-aware
        // descriptions) would silently allocate three Strings per entry
        // per CLI startup. Pin lifetime via require_static_str on every
        // field of every tuple — symmetric to round-163 + round-165 +
        // round-168 + round-169 + round-170 + round-171 + round-173
        // static-str pins extended to operator scope catalogue.
        fn require_static_str(_: &'static str) {}
        for (scope, desc, endpoints) in SCOPE_CATALOGUE {
            require_static_str(scope);
            require_static_str(desc);
            require_static_str(endpoints);
        }
    }

    #[test]
    fn scope_catalogue_const_field_type_is_static_slice_of_three_tuple_for_compile_time_embed() {
        // SCOPE_CATALOGUE is `pub const` (not `pub static`) — the value
        // is compile-time-embedded into every binary that consumes the
        // crate (proxy + CLI + future SCIM bridge). A refactor to
        // `pub static SCOPE_CATALOGUE: Lazy<Vec<...>>` "for ergonomic
        // dynamic-loading" would silently move the catalogue from
        // .rodata into the heap AND would let i18n-aware descriptions
        // mutate per-binary, breaking the cross-tool consistency
        // contract. Pin the const-ness via a `const _: &[(&str, &str,
        // &str)] = SCOPE_CATALOGUE;` const-block which fails compile
        // if the type ever drifts.
        const _CATALOGUE_TYPE_PIN: &[(&str, &str, &str)] = SCOPE_CATALOGUE;
        // Type-level pin via direct slice access (the const block
        // above already checks at compile time; the runtime check
        // below is the corresponding value-level assertion).
        assert_eq!(_CATALOGUE_TYPE_PIN.len(), SCOPE_CATALOGUE.len());
    }

    #[test]
    fn scope_strings_returns_owned_vec_of_static_str_not_borrowed_slice() {
        // The helper returns `Vec<&'static str>` (owned outer Vec, but
        // borrowed-with-static-lifetime elements) — the &'static
        // elements let consumers store the result in a long-lived
        // HashSet without re-cloning. The existing pins walk the
        // count + ordering but never the TYPE-level contract. A
        // refactor returning `&'static [&'static str]` "to avoid the
        // Vec allocation" would silently let consumers Box and ship
        // it but break callers that mutate the Vec (the operator_auth
        // crate dedup-extends it with custom scopes). Pin
        // Vec<&'static str> via require_vec_static_str.
        fn require_vec_static_str(_: &Vec<&'static str>) {}
        let strs = scope_strings();
        require_vec_static_str(&strs);
        // Per-element 'static lifetime.
        fn require_static_str(_: &'static str) {}
        for s in &strs {
            require_static_str(s);
        }
    }

    #[test]
    fn scope_strings_is_referentially_transparent_across_fifty_repeated_calls() {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 + round-172 + round-173
        // referential-transparency pins extended to scope_strings. The
        // CLI's `tokens scopes` renderer may call this helper multiple
        // times during a single render (once for the table + once for
        // a per-scope lookup); a refactor caching results in a thread-
        // local mutable Vec "for hot-path perf" would silently return
        // a shared mutable reference if the lock was acquired
        // incorrectly. Pin 50 calls return byte-equal Vec contents.
        let baseline = scope_strings();
        for i in 0..50 {
            let again = scope_strings();
            assert_eq!(
                again, baseline,
                "iteration {i}: scope_strings must be referentially transparent",
            );
        }
        // Defensive: same length each time.
        assert_eq!(baseline.len(), SCOPE_CATALOGUE.len());
    }

    #[test]
    fn every_scope_string_is_at_least_one_char_and_at_most_thirty_two_chars_for_cli_table_layout() {
        // The CLI `tokens scopes` table renders scope strings in a
        // fixed-width column; the maximum is 32 chars (`killswitch:revoke`
        // is 17, the longest current). A refactor that introduced an
        // arbitrarily-long scope (`actions:export:csv:streaming:cursor:v2`)
        // "for ergonomic versioned scopes" would silently overflow the
        // table column AND silently widen the JWT bearer scope claim
        // beyond what existing IdPs allow (Okta caps custom claims at
        // ~256 bytes per scope). Pin a min-1 / max-32 length sweep so
        // a regression surfaces here on the CLI-layout + IdP-compat
        // contract.
        for (s, _, _) in SCOPE_CATALOGUE {
            assert!(!s.is_empty(), "scope must be at least 1 char: {s}");
            assert!(
                s.len() <= 32,
                "scope `{s}` is {} chars — exceeds 32-char CLI column",
                s.len(),
            );
        }
    }

    #[test]
    fn scope_catalogue_carries_exactly_twelve_entries_pinning_the_documented_set_byte_exact() {
        // The existing pin (`catalogue_carries_at_least_twelve_entries_per_documented_spec`)
        // walks a `>= 12` floor — never catches an accidental ADDITION
        // of a 13th scope that a future PR landed without updating
        // operator runbooks. Operator-runbook drift is one of the
        // top-3 ways a scope-write regression has historically
        // surfaced: someone adds `policy:delete` "to test a feature"
        // and ships to production without updating the CLI help, the
        // docs/error-codes.md catalogue, or the SCIM sync. Pin
        // EXACTLY 12 — symmetric to round-161 + round-165 + round-169
        // + round-171 + round-172 exhaustive-set pins extended to
        // SCOPE_CATALOGUE cardinality.
        assert_eq!(
            SCOPE_CATALOGUE.len(),
            12,
            "catalogue length changed to {} — add to docs/error-codes.md + operator runbook + bump this assertion",
            SCOPE_CATALOGUE.len(),
        );
    }
}
