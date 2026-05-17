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
}
