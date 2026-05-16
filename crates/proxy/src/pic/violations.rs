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
}
