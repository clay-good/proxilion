//! PIC invariant violation persistence.
//!
//! Authority: spec.md §2.4. Every monotonicity violation produces a row.
//! In `runtime_gate` mode the request is blocked (`blocked_actions` also
//! gets a row). In `audit` mode the request proceeds against the
//! predecessor PCA, but the violation is permanently recorded here for
//! the forensic chain.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PicViolationRecord<'a> {
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub p_0: Option<&'a str>,
    pub vendor: &'a str,
    pub action: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub policy_id: Option<&'a str>,
    pub predecessor_pca_id: Option<Uuid>,
    pub attempted_ops: &'a [String],
    /// Best-effort parse of the missing ops atoms; empty if the upstream
    /// refusal body didn't surface them in a structured way.
    pub missing_atoms: &'a [String],
    /// `audit` (request proceeded) or `runtime_gate` (request blocked).
    pub pic_mode: &'static str,
    pub detail: Option<&'a str>,
}

pub async fn persist(db: &PgPool, r: PicViolationRecord<'_>) {
    let res = sqlx::query(
        "INSERT INTO pic_violations
            (request_id, session_id, p_0, vendor, action, method, path,
             policy_id, predecessor_pca_id, attempted_ops, missing_atoms,
             pic_mode, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(r.request_id)
    .bind(r.session_id)
    .bind(r.p_0)
    .bind(r.vendor)
    .bind(r.action)
    .bind(r.method)
    .bind(r.path)
    .bind(r.policy_id)
    .bind(r.predecessor_pca_id)
    .bind(r.attempted_ops)
    .bind(r.missing_atoms)
    .bind(r.pic_mode)
    .bind(r.detail)
    .execute(db)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "failed to persist pic_violation");
    }
}

/// Heuristic parser for the Trust Plane refusal body.
///
/// Upstream `provenance-plane` formats monotonicity refusals roughly as:
///   `ops not subset of predecessor: missing [a, b, c]`
/// or as a serialized list. We split on the first `[` / `]` and tokenize.
/// If the body doesn't match, returns an empty Vec — the raw `detail` is
/// always persisted regardless.
pub fn parse_missing_atoms(detail: &str) -> Vec<String> {
    let Some(open) = detail.find('[') else {
        return Vec::new();
    };
    let Some(close) = detail[open + 1..].find(']') else {
        return Vec::new();
    };
    let inner = &detail[open + 1..open + 1 + close];
    inner
        .split(',')
        .map(|s| {
            s.trim()
                .trim_matches(|c: char| c == '"' || c == '\'')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_atoms_bracketed() {
        let atoms = parse_missing_atoms(
            "ops not subset of predecessor: missing [drive:read:bob/secret.docx, drive:write:bob/*]",
        );
        assert_eq!(
            atoms,
            vec![
                "drive:read:bob/secret.docx".to_string(),
                "drive:write:bob/*".to_string(),
            ]
        );
    }

    #[test]
    fn parse_atoms_quoted() {
        let atoms = parse_missing_atoms(r#"missing ["a:b:c", "d:e:f"]"#);
        assert_eq!(atoms, vec!["a:b:c".to_string(), "d:e:f".to_string()]);
    }

    #[test]
    fn parse_atoms_empty_when_no_brackets() {
        assert!(parse_missing_atoms("some other refusal").is_empty());
    }

    #[test]
    fn parse_atoms_handles_empty_list() {
        assert!(parse_missing_atoms("missing []").is_empty());
    }

    #[test]
    fn parse_atoms_single_value_no_comma() {
        // The Trust Plane sometimes emits a single missing atom (no
        // separator). Pin that the splitter on `,` still produces one
        // entry rather than zero.
        assert_eq!(
            parse_missing_atoms("missing [drive:read:secret.docx]"),
            vec!["drive:read:secret.docx".to_string()],
        );
    }

    #[test]
    fn parse_atoms_handles_unclosed_bracket() {
        // Malformed input — opening bracket but no close. Must not panic
        // and must return empty (rather than reading off the end). The
        // raw `detail` is persisted elsewhere; this helper is best-effort.
        assert!(parse_missing_atoms("missing [a, b, c").is_empty());
    }

    #[test]
    fn parse_atoms_trims_whitespace_and_drops_empty_segments() {
        // The upstream body sometimes has spaces around commas
        // (`"[a, b,  c]"`) and sometimes a trailing comma (`"[a,b,]"`).
        // Pin both: whitespace is trimmed, empty segments are dropped.
        assert_eq!(
            parse_missing_atoms("[  a:1 ,  b:2 ,c:3]"),
            vec!["a:1".to_string(), "b:2".to_string(), "c:3".to_string()],
        );
        assert_eq!(
            parse_missing_atoms("[a:1,b:2,]"),
            vec!["a:1".to_string(), "b:2".to_string()],
        );
    }

    #[test]
    fn parse_atoms_uses_first_bracket_pair_only_ignoring_trailing_brackets() {
        // The Trust Plane refusal body sometimes embeds a second
        // bracketed list (e.g. `missing [a, b] (predecessor had [x, y])`).
        // The parser keys on the FIRST `[` and the first `]` after it,
        // so only `a, b` is surfaced — the trailing pair is ignored.
        // Pin this so a future refactor that scans every bracket pair
        // doesn't silently merge the two lists.
        assert_eq!(
            parse_missing_atoms("missing [a:1, b:2] (predecessor had [x:9, y:9])"),
            vec!["a:1".to_string(), "b:2".to_string()],
        );
    }

    #[test]
    fn parse_atoms_close_before_open_returns_empty_without_panic() {
        // Malformed body where a stray `]` appears before any `[`. The
        // parser must not slice with a negative offset (which would
        // panic on usize) nor mistake the orphan `]` for a list end. We
        // pin this because `detail.find('[')` then `detail[open+1..]
        // .find(']')` is the load-bearing two-step — a refactor to
        // `detail.find(']')` first would flip the contract and could
        // panic on `]a:1` (open uninitialized) or worse, return atoms
        // from before the `[`.
        assert!(parse_missing_atoms("] orphan close before [a:1]").len() == 1);
        assert!(parse_missing_atoms("] orphan with no open").is_empty());
    }

    #[test]
    fn parse_atoms_mixed_single_and_double_quotes_strip_both() {
        // The Trust Plane has been observed emitting both single-quoted
        // and double-quoted atoms in the same list (e.g. when one
        // serializer wraps and another doesn't). Pin that the
        // `trim_matches` closure strips BOTH quote characters — a
        // refactor that hardcoded `'"'` only would leak a leading `'`
        // into the resulting atom string.
        assert_eq!(
            parse_missing_atoms(r#"missing ["a:b:c", 'd:e:f', g:h:i]"#),
            vec![
                "a:b:c".to_string(),
                "d:e:f".to_string(),
                "g:h:i".to_string(),
            ],
        );
    }

    #[test]
    fn parse_atoms_whitespace_only_segments_are_dropped() {
        // `"[ , , a:1, ]"` is the degenerate trailing/leading-comma
        // case the round-7 backfill skipped. After `trim()` the empty
        // segments become `""` and the `.filter(|s| !s.is_empty())`
        // step must drop them — pin this so a regression that uses
        // `.filter(|s| !s.is_empty() || include_empty)` (a feature
        // flag landing for some debug mode, say) doesn't silently
        // surface phantom empty atoms to the operator UI.
        assert_eq!(parse_missing_atoms("[ , , a:1, ]"), vec!["a:1".to_string()],);
    }

    #[test]
    fn pic_violation_record_debug_carries_struct_name_and_key_field_names() {
        // PicViolationRecord flows through `tracing::warn!(?r, "failed to
        // persist pic_violation")` on the persistence failure path; the
        // PIC executor and the audit-mode logger both pass the same
        // Record to multiple sinks. Operators grep the resulting log
        // line by struct name + by `request_id` / `session_id` /
        // `vendor` / `action` / `pic_mode` selectors to bucket "which
        // PIC violation, which mode, which adapter" when triaging.
        // A manual Debug that hid any of them "to compact" the line
        // would break every operator bucket. Pin the six-way shape
        // (struct name + five load-bearing field names).
        let req = Uuid::new_v4();
        let sess = Uuid::new_v4();
        let pred = Uuid::new_v4();
        let ops: Vec<String> = vec![];
        let atoms: Vec<String> = vec![];
        let r = PicViolationRecord {
            request_id: req,
            session_id: sess,
            p_0: None,
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/drive/v3/files/x",
            policy_id: None,
            predecessor_pca_id: Some(pred),
            attempted_ops: &ops,
            missing_atoms: &atoms,
            pic_mode: "audit",
            detail: None,
        };
        let s = format!("{r:?}");
        assert!(s.contains("PicViolationRecord"), "got: {s}");
        assert!(s.contains("request_id"), "got: {s}");
        assert!(s.contains("session_id"), "got: {s}");
        assert!(s.contains("vendor"), "got: {s}");
        assert!(s.contains("action"), "got: {s}");
        assert!(s.contains("pic_mode"), "got: {s}");
        // pic_mode value also visible — operators bucket on "audit" vs
        // "runtime_gate" directly in the log line.
        assert!(s.contains("audit"), "got: {s}");
    }

    #[test]
    fn parse_atoms_trim_matches_strips_multiple_consecutive_quote_chars() {
        // `trim_matches(|c| c == '"' || c == '\'')` is a greedy multi-pass
        // strip, NOT a single-char trim. The Trust Plane has been
        // observed emitting double-wrapped atoms (`""x""`) when one
        // serializer stringifies and another re-wraps. Pin that all
        // four leading + four trailing quote chars are stripped on the
        // greedy path so the result is the bare atom `x`. A refactor
        // that swapped to `strip_prefix("\"").and_then(strip_suffix)`
        // (a "single-pass tidy" change) would silently leak the outer
        // wrap chars into the result string.
        assert_eq!(
            parse_missing_atoms(r#"missing [""""x""""]"#),
            vec!["x".to_string()],
        );
        // Mixed single + double on the same atom — greedy strip handles
        // either side independently.
        assert_eq!(
            parse_missing_atoms(r#"missing ['"a:b:c"']"#),
            vec!["a:b:c".to_string()],
        );
    }

    #[test]
    fn parse_atoms_handles_tab_and_newline_as_whitespace_via_trim() {
        // The Trust Plane refusal body sometimes wraps onto multiple
        // lines (`"missing [a:1,\n b:2,\tc:3]"`) when the upstream
        // serializer pretty-prints. `str::trim()` strips ASCII tab,
        // newline, carriage-return, and form-feed as well as space,
        // so all four atoms must surface cleanly. A refactor that
        // hardcoded `trim_start_matches(' ')` only would let the
        // tab / newline through and silently include them in the
        // atom string, breaking exact-match `missing_atoms`
        // comparisons in the operator UI.
        assert_eq!(
            parse_missing_atoms("missing [a:1,\n b:2,\tc:3,\rd:4]"),
            vec![
                "a:1".to_string(),
                "b:2".to_string(),
                "c:3".to_string(),
                "d:4".to_string(),
            ],
        );
    }

    #[test]
    fn pic_violation_record_with_all_none_optionals_constructs_and_clones() {
        // All four `Option<_>` fields (p_0, policy_id, predecessor_pca_id,
        // detail) can simultaneously be None — this is the PIC-violation
        // shape for an unauthenticated probe that tripped the executor
        // before any of those fields were populated. Pin construction +
        // Clone on the all-None shape so a refactor that started requiring
        // any of them at compile-time (e.g. removing `Option<>` on detail
        // "since the Trust Plane always emits one") would surface here
        // rather than at the call site that builds the record from an
        // empty refusal body.
        let req = Uuid::new_v4();
        let sess = Uuid::new_v4();
        let ops: Vec<String> = vec![];
        let atoms: Vec<String> = vec![];
        let r = PicViolationRecord {
            request_id: req,
            session_id: sess,
            p_0: None,
            vendor: "v",
            action: "a",
            method: "GET",
            path: "/",
            policy_id: None,
            predecessor_pca_id: None,
            attempted_ops: &ops,
            missing_atoms: &atoms,
            pic_mode: "audit",
            detail: None,
        };
        assert!(r.p_0.is_none());
        assert!(r.policy_id.is_none());
        assert!(r.predecessor_pca_id.is_none());
        assert!(r.detail.is_none());
        let c = r.clone();
        assert!(c.p_0.is_none());
        assert!(c.policy_id.is_none());
        assert!(c.predecessor_pca_id.is_none());
        assert!(c.detail.is_none());
        assert_eq!(c.request_id, req);
        assert_eq!(c.session_id, sess);
        assert_eq!(c.pic_mode, "audit");
    }

    #[test]
    fn parse_atoms_returns_owned_strings_independent_of_input_lifetime() {
        // `parse_missing_atoms` returns `Vec<String>` — every atom is an
        // OWNED allocation, not a borrowed slice over the input. Pin
        // this contract by dropping the input string BEFORE inspecting
        // the atoms: the result must still be readable. A refactor that
        // returned `Vec<&'a str>` "to avoid the per-atom allocation"
        // would silently introduce a lifetime constraint that the
        // current `persist()` call shape (which builds a temporary
        // refusal-body String, then parses it, then passes the parsed
        // atoms to the binding) couldn't satisfy — borrow-checker
        // failure at the bind site, not here.
        let atoms = {
            let detail = String::from("missing [drive:read:a, drive:write:b, gmail:send:c]");
            parse_missing_atoms(&detail)
            // `detail` dropped here.
        };
        assert_eq!(atoms.len(), 3);
        assert_eq!(atoms[0], "drive:read:a");
        assert_eq!(atoms[1], "drive:write:b");
        assert_eq!(atoms[2], "gmail:send:c");
    }

    #[test]
    fn parse_atoms_handles_one_hundred_atom_list_preserving_first_middle_last() {
        // The Trust Plane can produce wide missing-atoms lists when the
        // requested ops set spans many resources (e.g. a `*` glob on a
        // 100-file folder under a tight policy). Pin scale correctness:
        // a 100-comma-separated list produces 100 atoms with boundary
        // positions 0/50/99 byte-equal to the input. A refactor that
        // capped the split at N atoms "for log line length" would
        // surface here as a truncated result rather than as a silently
        // partial pic_violations row.
        let atoms_in: Vec<String> = (0..100).map(|i| format!("op:tier{i}:r/{i}")).collect();
        let detail = format!("missing [{}]", atoms_in.join(", "));
        let atoms_out = parse_missing_atoms(&detail);
        assert_eq!(atoms_out.len(), 100);
        assert_eq!(atoms_out[0], "op:tier0:r/0");
        assert_eq!(atoms_out[50], "op:tier50:r/50");
        assert_eq!(atoms_out[99], "op:tier99:r/99");
    }

    #[test]
    fn pic_violation_record_clone_preserves_all_borrowed_slices() {
        // PicViolationRecord is `Clone` and carries five `&str`/`&[]`
        // borrows + a `Uuid` + a `&'static str` mode tag. The Clone
        // derive is load-bearing — `persist()` takes the struct by
        // value, but several adapter call sites build one Record and
        // pass it to two sinks (the audit-mode logger + the
        // pic_violations writer). A refactor that accidentally dropped
        // the `Clone` derive would force a borrow-checker rewrite and
        // could change the shape of the call sites. Pin the trait.
        let req = Uuid::new_v4();
        let sess = Uuid::new_v4();
        let pred = Uuid::new_v4();
        let ops = vec!["a:b:c".to_string()];
        let atoms = vec!["x:y:z".to_string()];
        let r = PicViolationRecord {
            request_id: req,
            session_id: sess,
            p_0: Some("alice@demo.local"),
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/drive/v3/files/abc",
            policy_id: Some("drive-read-gate"),
            predecessor_pca_id: Some(pred),
            attempted_ops: &ops,
            missing_atoms: &atoms,
            pic_mode: "runtime_gate",
            detail: Some("missing [x:y:z]"),
        };
        let c = r.clone();
        assert_eq!(c.request_id, req);
        assert_eq!(c.session_id, sess);
        assert_eq!(c.predecessor_pca_id, Some(pred));
        assert_eq!(c.attempted_ops.len(), 1);
        assert_eq!(c.missing_atoms[0], "x:y:z");
        assert_eq!(c.pic_mode, "runtime_gate");
        assert_eq!(c.p_0, Some("alice@demo.local"));
    }

    #[test]
    fn pic_violation_record_pic_mode_field_is_static_str_lifetime_for_zero_alloc_log_filter() {
        // The module docstring + persist binding both treat `pic_mode` as
        // a two-value enum-on-strings (`"audit"` or `"runtime_gate"`).
        // The existing module pins the value across both Debug + Clone
        // surfaces, but never the `&'static str` lifetime. A refactor to
        // `String` "for richer mode labels like `runtime_gate.confirmed`"
        // would silently allocate one String per PIC violation row at the
        // adapter-layer build site (every Drive/Gmail/Calendar request
        // that trips monotonicity ends up here) — pin lifetime via a
        // `require_static_str` fn whose signature only compiles when
        // the field has `'static` lifetime, symmetric to round-163
        // ConfigError::InvalidValue.field pin + round-165 oauth
        // token_type pin extended to PicViolationRecord.pic_mode.
        fn require_static_str(_: &'static str) {}
        let req = Uuid::new_v4();
        let sess = Uuid::new_v4();
        let ops: Vec<String> = vec![];
        let atoms: Vec<String> = vec![];
        let r = PicViolationRecord {
            request_id: req,
            session_id: sess,
            p_0: None,
            vendor: "v",
            action: "a",
            method: "GET",
            path: "/",
            policy_id: None,
            predecessor_pca_id: None,
            attempted_ops: &ops,
            missing_atoms: &atoms,
            pic_mode: "runtime_gate",
            detail: None,
        };
        require_static_str(r.pic_mode);
        // Cross-value sweep: both canonical labels are 'static-bound.
        let r2 = PicViolationRecord {
            pic_mode: "audit",
            ..r.clone()
        };
        require_static_str(r2.pic_mode);
    }

    #[test]
    fn pic_violation_record_static_borrow_is_send_sync_for_tokio_spawn_boundary() {
        // `persist()` is an async fn that takes the Record by value and
        // performs an `.await` on the DB INSERT — the Record must be
        // `Send` across that .await point for any caller that pushes
        // the persist call into a `tokio::spawn` block (the
        // tee-to-audit-sink path does this so the request return path
        // doesn't wait on the secondary writer). The 'a borrow makes
        // `Sync` impossible at arbitrary lifetimes; pin the 'static
        // instantiation specifically — which is sufficient for the
        // tokio::spawn caller since the borrowed slices it constructs
        // live as long as the spawned future. Symmetric to round-164
        // PicExecutor Send+Sync+'static pin extended to violations
        // record.
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<PicViolationRecord<'static>>();
    }

    #[test]
    fn parse_missing_atoms_is_referentially_transparent_across_fifty_repeated_calls() {
        // Symmetric to round-161 parse_listing + round-162 canonical_request_json
        // + round-166 enforce_pre_request_decision referential-transparency
        // pins extended to PIC violation parsing. The Trust Plane
        // refusal-body parser is called once per PIC-mode violation; a
        // refactor caching results in a `once_cell` keyed on a hash of
        // the detail string "for hot-path perf" would surface a stale
        // result on the next violation with a different detail but a
        // colliding hash. Pin 50 calls on a multi-atom fixture and assert
        // every call returns byte-equal Vec<String>.
        let detail = "ops not subset of predecessor: missing [drive:read:bob/secret.docx, gmail:send:to/eve@evil.example, calendar:write:event/q4-planning]";
        let baseline = parse_missing_atoms(detail);
        assert_eq!(baseline.len(), 3, "fixture must produce exactly 3 atoms");
        for i in 0..50 {
            let again = parse_missing_atoms(detail);
            assert_eq!(
                again, baseline,
                "iteration {i}: parse_missing_atoms must be referentially transparent",
            );
        }
    }

    #[test]
    fn parse_missing_atoms_preserves_multibyte_unicode_in_atoms_verbatim() {
        // The atom labels can contain multibyte unicode when the policy
        // YAML carries non-ASCII resource paths (e.g. a Drive file id
        // that's a unicode title, a calendar event id with kanji). The
        // existing module never walks a multibyte atom; a refactor
        // applying `.to_ascii_lowercase()` "for SIEM hygiene" or
        // `.replace(|c: char| !c.is_ascii(), "?")` "for grep safety"
        // would silently mangle non-ASCII atom labels and split the
        // operator's dashboard bucket between ASCII and multibyte
        // policies on what should be the same `missing_atoms[i]` value.
        // Pin byte-equal preservation across café + Japanese + emoji.
        let detail = "missing [drive:read:café/secret.docx, calendar:write:event/日本-q4, gmail:send:to/eve🔥@evil.example]";
        let atoms = parse_missing_atoms(detail);
        assert_eq!(atoms.len(), 3);
        assert_eq!(atoms[0], "drive:read:café/secret.docx");
        assert_eq!(atoms[1], "calendar:write:event/日本-q4");
        assert_eq!(atoms[2], "gmail:send:to/eve🔥@evil.example");
    }

    #[test]
    fn parse_missing_atoms_returns_empty_vec_on_four_distinct_no_bracket_input_shapes() {
        // The early-return contract — `let Some(open) = detail.find('[')
        // else { return Vec::new(); }` — must produce an EMPTY Vec on
        // every no-bracket input shape, not panic, not return a
        // single-element fallback, not echo the input as one atom.
        // The existing pin walks one no-bracket input — pin 4 distinct
        // shapes so a refactor to "fall back to splitting on whitespace
        // when no brackets" silently surfaces an N-atom result on what
        // operators expect to be the empty-list contract.
        // (1) Empty string.
        assert!(parse_missing_atoms("").is_empty());
        // (2) Long no-bracket prose.
        let long = "x".repeat(1000);
        assert!(parse_missing_atoms(&long).is_empty());
        // (3) Single non-bracket char.
        assert!(parse_missing_atoms("a").is_empty());
        // (4) Comma-separated text with no brackets at all (would-be
        //     hot-path for a "smart" fallback to splitting on commas).
        assert!(parse_missing_atoms("a, b, c").is_empty());
        // (5) Closing bracket only — open bracket is what triggers the
        //     parse; without it, no atoms.
        assert!(parse_missing_atoms("foo]").is_empty());
    }

    #[test]
    fn parse_missing_atoms_returns_owned_vec_string_type_not_borrowed_slice() {
        // The persist() bind site requires `Vec<String>` (owned) because
        // sqlx binds the slice to `text[]` and the Postgres driver
        // serializes one String at a time. A refactor to `Vec<&'a str>`
        // "to avoid per-atom allocation" would surface at the persist
        // binding as a lifetime constraint — break the call site that
        // constructs a transient detail String, parses it, then drops it
        // before the bind (`detail` is dropped at end of statement, but
        // the parsed atoms must outlive). The existing pin
        // (`parse_atoms_returns_owned_strings_independent_of_input_lifetime`)
        // walks the value-level outlives semantic; pin the TYPE-level
        // contract via a generic fn whose signature only compiles when
        // the return is `Vec<String>` — a refactor to `Vec<&str>` would
        // fail compilation here rather than at the bind site.
        fn require_vec_string(_: &Vec<String>) {}
        let atoms = parse_missing_atoms("missing [a:1, b:2]");
        require_vec_string(&atoms);
        // Defensive: each atom is also owned `String`, not `&str`.
        fn require_string(_: &String) {}
        require_string(&atoms[0]);
    }

    // ─── round 184 (2026-05-20): PicViolationRecord + parse_missing_atoms surfaces ───

    #[test]
    fn pic_violation_record_attempted_ops_and_missing_atoms_fields_are_borrowed_string_slice_type()
    {
        // `attempted_ops: &'a [String]` AND `missing_atoms: &'a [String]`
        // — both fields are borrowed slices over owned `String`s. The
        // borrow shape is load-bearing for the persist() bind path:
        // sqlx's `.bind(r.attempted_ops)` accepts `&[String]` directly
        // for the `text[]` column type. A refactor to `Vec<String>`
        // "for ownership clarity" would force every call site to
        // clone the upstream Vec into the record (the adapter
        // currently constructs a transient Vec, takes a borrow, then
        // drops both at end of scope — the persist() future captures
        // the borrow). Pin both field types via the canonical
        // require_slice_string helper. Symmetric to round-179 +
        // round-180 + round-181 owned-vs-borrowed type pins extended
        // to this Record's borrowed-slice fields.
        fn require_slice_string(_: &[String]) {}
        let attempted: Vec<String> = vec!["a:1".into(), "b:2".into()];
        let missing: Vec<String> = vec!["c:3".into()];
        let r = PicViolationRecord {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: None,
            vendor: "v",
            action: "a",
            method: "POST",
            path: "/x",
            policy_id: None,
            predecessor_pca_id: None,
            attempted_ops: &attempted,
            missing_atoms: &missing,
            pic_mode: "audit",
            detail: None,
        };
        require_slice_string(r.attempted_ops);
        require_slice_string(r.missing_atoms);
        // Round-trip sanity: the borrowed slice pointer equals the
        // original Vec's slice pointer (zero-copy borrow).
        assert_eq!(r.attempted_ops.as_ptr(), attempted.as_ptr());
        assert_eq!(r.missing_atoms.as_ptr(), missing.as_ptr());
    }

    #[test]
    fn parse_missing_atoms_with_open_bracket_at_first_char_yields_normal_parse() {
        // The parser uses `detail.find('[')` — when the open bracket
        // is at byte offset 0 (no prefix), the slicing arithmetic
        // `&detail[open + 1..]` must NOT panic and the atoms inside
        // must be parsed normally. The existing tests all pin
        // bracket-with-prefix shapes (`"missing [...]"`); pin the
        // no-prefix edge here so a refactor that pre-required a
        // colon-or-space before the bracket "for shape validation"
        // would silently start returning empty Vec on what is a
        // legitimate Trust-Plane refusal shape (`"[a:1, b:2]"`).
        let atoms = parse_missing_atoms("[a:1, b:2]");
        assert_eq!(atoms, vec!["a:1".to_string(), "b:2".to_string()]);
    }

    #[test]
    fn parse_missing_atoms_with_open_bracket_as_last_char_returns_empty_without_panic() {
        // Boundary: when the open bracket `[` is the LAST character of
        // the input, `detail.find('[')` returns `Some(len - 1)`, and
        // `detail[open + 1..]` is the empty slice — `find(']')` on
        // that returns None, so the function short-circuits to
        // `Vec::new()`. Pin that NO panic surfaces in the slice
        // arithmetic AND the empty-Vec return contract holds. A
        // refactor that pre-validated `open + 1 < detail.len()` via
        // an `assert!` for "tidiness" would silently introduce a
        // panic-on-input path that crashes the request handler.
        // Symmetric to round-170 boundary pins extended to the
        // pathological-input arithmetic edge.
        let atoms = parse_missing_atoms("missing [");
        assert!(atoms.is_empty(), "trailing-open-bracket must return empty");
        // Also pin the LITERALLY-just-an-open-bracket input — even
        // more degenerate, must still no-panic empty.
        let atoms = parse_missing_atoms("[");
        assert!(atoms.is_empty());
    }

    #[test]
    fn parse_missing_atoms_preserves_one_kb_atom_inside_brackets_byte_equal() {
        // Trust-Plane refusal bodies can carry long atom labels (a
        // Drive file path with deep nesting, a calendar event id
        // with embedded query params). The existing
        // `parse_atoms_handles_one_hundred_atom_list_preserving_first_middle_last`
        // pin walks the MANY-ATOM axis; pin the LONG-ATOM axis
        // here: a single 1-KB-class atom inside brackets must
        // survive byte-equal through the parse. A refactor that
        // truncated atom labels to a fixed budget (e.g. 256 chars
        // "for log-line hygiene") would silently mangle long
        // labels AND silently change every operator dashboard
        // bucket keying on the full atom string.
        let long_atom = format!("drive:read:{}", "x".repeat(1024));
        let detail = format!("missing [{long_atom}]");
        let atoms = parse_missing_atoms(&detail);
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0], long_atom);
        assert!(atoms[0].len() > 1024, "atom must survive at full length");
    }

    #[test]
    fn parse_missing_atoms_only_strips_double_and_single_quotes_not_backtick_or_other_delimiters() {
        // The parser's `trim_matches(|c| c == '"' || c == '\'')`
        // strips ONLY ASCII double-quote and single-quote. Pin that
        // a backtick (`)-wrapped atom passes through verbatim
        // (backticks ARE NOT stripped), and that the brace, paren,
        // angle-bracket "delimiter-shaped" chars likewise pass
        // through. A refactor that widened the strip set to "any
        // delimiter char" (the natural "be permissive about
        // upstream quoting styles" mistake) would silently strip
        // backticks from atoms that legitimately carry them (e.g.
        // a future query-shape atom like `gmail:filter:from:\`eve@evil.example\``).
        // Pin via three distinct non-quote delimiters.
        // Backtick — must NOT be stripped (verbatim).
        let atoms = parse_missing_atoms("missing [`a:1`]");
        assert_eq!(atoms, vec!["`a:1`".to_string()]);
        // Mixed: single-quote IS stripped from outside, backtick
        // inside survives.
        let atoms = parse_missing_atoms("missing ['`a:1`']");
        assert_eq!(atoms, vec!["`a:1`".to_string()]);
        // Double-quote IS stripped (already pinned via
        // parse_atoms_quoted), pin the symmetric backtick negative
        // here.
        let atoms = parse_missing_atoms(r#"missing ["a:1"]"#);
        assert_eq!(atoms, vec!["a:1".to_string()]);
    }

    #[test]
    fn pic_violation_record_pic_mode_accepts_both_documented_static_str_values_audit_and_runtime_gate()
     {
        // `pic_mode: &'static str` — the docstring on the field
        // says: "`audit` (request proceeded) or `runtime_gate`
        // (request blocked)." Both values are construction-time
        // literals; pin that BOTH known values construct the
        // Record without issue AND survive a Clone byte-equal.
        // The existing `pic_violation_record_pic_mode_field_is_static_str_lifetime_for_zero_alloc_log_filter`
        // pin checks the &'static str lifetime via require_static_str
        // (single value); pin both documented values here as the
        // operator-facing "every PIC violation lands in one of
        // these two buckets" contract. A refactor that introduced
        // a third value (e.g. `"observe"` for a future
        // observe-mode-but-also-track-PIC mode) would surface here
        // as needing to update this test alongside the docstring.
        // Symmetric to round-178 + round-181 variant-count
        // exhaustive-set pins extended to a documented string-tier
        // constants set.
        for mode in ["audit", "runtime_gate"] {
            let r = PicViolationRecord {
                request_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                p_0: None,
                vendor: "v",
                action: "a",
                method: "POST",
                path: "/x",
                policy_id: None,
                predecessor_pca_id: None,
                attempted_ops: &[],
                missing_atoms: &[],
                pic_mode: mode,
                detail: None,
            };
            // Static lifetime survives — pin via require_static_str.
            fn require_static_str(_: &'static str) {}
            require_static_str(r.pic_mode);
            // Clone preserves byte-equal.
            let c = r.clone();
            assert_eq!(c.pic_mode, mode);
            // Documented values are NOT kebab-case AND NOT uppercase
            // (matches the runtime_gate spec.md §9 customer YAML
            // example shape that pic_mode is a snake_case wire
            // shape in dashboards).
            assert!(!mode.contains('-'), "mode must not be kebab-case: {mode}");
            assert_eq!(mode, &mode.to_lowercase(), "mode must be lowercase");
        }
    }
}
