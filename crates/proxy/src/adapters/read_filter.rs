//! Apply a `ReadFilter` (quarantine patterns + action) to a response body.
//!
//! Authority: spec.md §1.4. We compile every pattern (literal *or* regex)
//! into one `RegexSet` for fast short-circuit "any-match" testing — then
//! iterate per-pattern `Regex` for position resolution only on the patterns
//! that `RegexSet` reported as matching. Literals are escaped before
//! compilation so they share the same engine.

use policy_engine::decision::{Pattern, QuarantineAction, ReadFilter};
use regex::{Regex, RegexSet};

/// Marker substituted in place of a quarantined match when the filter's
/// action is `ReplaceWithMarker`.
pub const MARKER: &str = "[redacted by proxilion read-filter]";

#[derive(Debug, Default)]
pub struct FilterOutcome {
    pub matches: usize,
    pub triggered: bool,
    /// Snippets of the matched text, for the `quarantined_payloads` audit
    /// row. Each snippet is the matched substring truncated to 200 chars,
    /// paired with the human-readable pattern source.
    pub samples: Vec<QuarantineSample>,
    /// Whether the caller should block the request (`BlockRequest` action).
    pub block: bool,
}

#[derive(Debug, Clone)]
pub struct QuarantineSample {
    pub pattern: String,
    pub snippet: String,
}

/// Compiled form of a `ReadFilter` — held by the adapter and reused across
/// requests. Building once per filter saves regex compilation on the hot path.
pub struct CompiledFilter {
    set: RegexSet,
    per_pattern: Vec<(Regex, String)>, // (regex, source-for-audit)
    action: QuarantineAction,
}

impl CompiledFilter {
    pub fn compile(filter: &ReadFilter) -> Result<Self, regex::Error> {
        let mut sources = Vec::with_capacity(filter.quarantine_patterns.len());
        let mut audit = Vec::with_capacity(filter.quarantine_patterns.len());
        for p in &filter.quarantine_patterns {
            match p {
                Pattern::Literal(s) => {
                    sources.push(regex::escape(s));
                    audit.push(format!("literal: {}", truncate(s, 80)));
                }
                Pattern::Regex(r) => {
                    sources.push(r.as_str().to_owned());
                    audit.push(format!("regex: {}", truncate(r.as_str(), 80)));
                }
            }
        }
        let set = RegexSet::new(&sources)?;
        let per_pattern = sources
            .into_iter()
            .zip(audit)
            .map(|(s, src)| Ok::<_, regex::Error>((Regex::new(&s)?, src)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            set,
            per_pattern,
            action: filter.quarantine_action,
        })
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// Returns the (possibly rewritten) body. Does *not* publish quarantine rows
/// to the DB — that's the adapter's responsibility.
pub fn apply(
    body: &[u8],
    filter: &CompiledFilter,
    content_type: Option<&str>,
) -> (Vec<u8>, FilterOutcome) {
    if !should_scan(content_type) {
        return (body.to_vec(), FilterOutcome::default());
    }
    let text = String::from_utf8_lossy(body).into_owned();

    // Short-circuit: RegexSet test before any per-pattern work.
    let hits = filter.set.matches(&text);
    if !hits.matched_any() {
        return (text.into_bytes(), FilterOutcome::default());
    }

    let mut out = FilterOutcome::default();
    let mut all_ranges: Vec<(usize, usize)> = Vec::new();

    for idx in hits.iter() {
        let (re, src) = &filter.per_pattern[idx];
        for m in re.find_iter(&text) {
            all_ranges.push((m.start(), m.end()));
            out.matches += 1;
            out.samples.push(QuarantineSample {
                pattern: src.clone(),
                snippet: text[m.start()..m.end()].chars().take(200).collect(),
            });
        }
    }
    out.triggered = !all_ranges.is_empty();

    if matches!(filter.action, QuarantineAction::BlockRequest) {
        out.block = true;
        return (text.into_bytes(), out);
    }

    // Sort + merge overlapping ranges so replacement is deterministic.
    all_ranges.sort_by_key(|r| r.0);
    let merged = merge_overlapping(&all_ranges);

    let repl = match filter.action {
        QuarantineAction::ReplaceWithMarker => MARKER,
        QuarantineAction::StripSilently => "",
        QuarantineAction::BlockRequest => unreachable!(),
    };
    let rewritten = splice(&text, &merged, repl);
    (rewritten.into_bytes(), out)
}

fn should_scan(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return true };
    let main = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    main == "application/json" || main == "application/xml" || main.starts_with("text/")
}

fn merge_overlapping(sorted: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for &(s, e) in sorted {
        match out.last_mut() {
            Some(last) if last.1 >= s => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn splice(s: &str, ranges: &[(usize, usize)], repl: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for &(start, end) in ranges {
        out.push_str(&s[cursor..start]);
        out.push_str(repl);
        cursor = end;
    }
    out.push_str(&s[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_engine::decision::Pattern;
    use regex::Regex;

    fn build(action: QuarantineAction, patterns: Vec<Pattern>) -> CompiledFilter {
        CompiledFilter::compile(&ReadFilter {
            quarantine_patterns: patterns,
            quarantine_action: action,
        })
        .unwrap()
    }

    #[test]
    fn replaces_literal_with_marker() {
        let f = build(
            QuarantineAction::ReplaceWithMarker,
            vec![Pattern::Literal("ignore previous instructions".into())],
        );
        let (out, o) = apply(
            b"hello ignore previous instructions world",
            &f,
            Some("text/plain"),
        );
        assert_eq!(o.matches, 1);
        assert!(o.triggered);
        assert_eq!(o.samples.len(), 1);
        assert!(o.samples[0].pattern.starts_with("literal:"));
        assert!(String::from_utf8_lossy(&out).contains(MARKER));
    }

    #[test]
    fn regex_match_strip() {
        let f = build(
            QuarantineAction::StripSilently,
            vec![Pattern::Regex(Regex::new(r"<\|.*?\|>").unwrap())],
        );
        let (out, o) = apply(b"prefix <|inject|> suffix", &f, Some("text/html"));
        assert_eq!(o.matches, 1);
        assert_eq!(String::from_utf8_lossy(&out), "prefix  suffix");
    }

    #[test]
    fn block_request_action_returns_block_flag() {
        let f = build(
            QuarantineAction::BlockRequest,
            vec![Pattern::Literal("system prompt:".into())],
        );
        let (_out, o) = apply(
            b"... system prompt: do bad things ...",
            &f,
            Some("text/plain"),
        );
        assert!(o.block);
        assert!(o.triggered);
    }

    #[test]
    fn binary_content_type_skipped() {
        let f = build(
            QuarantineAction::ReplaceWithMarker,
            vec![Pattern::Literal("system prompt:".into())],
        );
        let (out, o) = apply(
            b"system prompt: leaked in a binary blob",
            &f,
            Some("application/octet-stream"),
        );
        assert_eq!(o.matches, 0);
        assert_eq!(out, b"system prompt: leaked in a binary blob");
    }

    #[test]
    fn overlapping_ranges_collapse() {
        // Two literals that overlap; replacement should not produce nested markers.
        let f = build(
            QuarantineAction::ReplaceWithMarker,
            vec![
                Pattern::Literal("ignore previous".into()),
                Pattern::Literal("previous instructions".into()),
            ],
        );
        let (out, o) = apply(
            b"please ignore previous instructions now",
            &f,
            Some("text/plain"),
        );
        assert_eq!(o.matches, 2);
        let s = String::from_utf8_lossy(&out);
        // Only one marker, not "marker marker"
        assert_eq!(s.matches(MARKER).count(), 1);
    }

    /// p99 budget per spec.md §1.4: < 10ms on a realistic body.
    /// Enforced in release builds only.
    #[test]
    #[cfg_attr(debug_assertions, ignore)]
    fn p99_under_ten_ms_on_64kb_body() {
        // Mix: long body, several patterns, some matches.
        let f = build(
            QuarantineAction::ReplaceWithMarker,
            vec![
                Pattern::Literal("ignore previous instructions".into()),
                Pattern::Literal("system prompt:".into()),
                Pattern::Regex(Regex::new(r"<\|.*?\|>").unwrap()),
                Pattern::Regex(Regex::new(r"\bAPI[_-]?KEY\b").unwrap()),
            ],
        );
        let mut body = String::with_capacity(64 * 1024);
        for i in 0..2000 {
            body.push_str(&format!(
                "line {i}: lorem ipsum dolor sit amet, consectetur. <|maybe|> some api_key text.\n"
            ));
        }
        let bytes = body.into_bytes();
        // Warm-up.
        for _ in 0..20 {
            let _ = apply(&bytes, &f, Some("text/plain"));
        }
        let mut samples = Vec::with_capacity(200);
        for _ in 0..200 {
            let start = std::time::Instant::now();
            let _ = apply(&bytes, &f, Some("text/plain"));
            samples.push(start.elapsed());
        }
        samples.sort();
        let p99 = samples[(samples.len() as f64 * 0.99) as usize];
        assert!(
            p99 < std::time::Duration::from_millis(10),
            "p99 {:?} exceeds 10ms budget on 64KiB body",
            p99
        );
    }

    #[test]
    fn truncate_helper_keeps_short_unchanged_and_ellipsizes_long() {
        assert_eq!(truncate("short", 10), "short");
        // Boundary: exactly the limit is unchanged (no ellipsis).
        assert_eq!(truncate("abcde", 5), "abcde");
        let long: String = "a".repeat(20);
        let out = truncate(&long, 5);
        assert_eq!(out.chars().count(), 6); // 5 + ellipsis char
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_uses_char_count_not_byte_len() {
        // 6 multi-byte chars, well under the 10-char limit but > 10 bytes.
        let s = "αβγδεζ";
        assert!(s.len() > 10, "precondition: byte len > char limit");
        assert_eq!(truncate(s, 10), s);
        assert_eq!(truncate(s, 3), "αβγ…");
    }

    #[test]
    fn should_scan_decides_by_content_type() {
        assert!(should_scan(None), "no content-type defaults to scan");
        assert!(should_scan(Some("application/json")));
        assert!(should_scan(Some("application/json; charset=utf-8")));
        assert!(should_scan(Some("APPLICATION/JSON"))); // case-insensitive
        assert!(should_scan(Some("application/xml")));
        assert!(should_scan(Some("text/html")));
        assert!(should_scan(Some("text/plain; charset=ascii")));
        assert!(!should_scan(Some("application/octet-stream")));
        assert!(!should_scan(Some("image/png")));
        assert!(!should_scan(Some("application/pdf")));
    }

    #[test]
    fn merge_overlapping_collapses_touching_and_overlapping_ranges() {
        // Disjoint stays separate.
        assert_eq!(merge_overlapping(&[(0, 3), (5, 8)]), vec![(0, 3), (5, 8)]);
        // Overlapping merges to max end.
        assert_eq!(merge_overlapping(&[(0, 5), (3, 8)]), vec![(0, 8)]);
        // Touching (end == next start) is treated as overlapping per `last.1 >= s`.
        assert_eq!(merge_overlapping(&[(0, 5), (5, 10)]), vec![(0, 10)]);
        // Nested inner range absorbed.
        assert_eq!(merge_overlapping(&[(0, 10), (3, 5)]), vec![(0, 10)]);
        // Empty input.
        assert_eq!(merge_overlapping(&[]), Vec::<(usize, usize)>::new());
    }

    #[test]
    fn splice_replaces_ranges_and_preserves_surroundings() {
        assert_eq!(splice("hello world", &[(6, 11)], "X"), "hello X");
        assert_eq!(splice("abcdef", &[(0, 2), (4, 6)], "_"), "_cd_");
        // No ranges -> identity.
        assert_eq!(splice("unchanged", &[], "X"), "unchanged");
        // Whole-string replacement.
        assert_eq!(splice("abc", &[(0, 3)], "Z"), "Z");
    }

    #[test]
    fn regexset_short_circuits_clean_bodies() {
        let f = build(
            QuarantineAction::ReplaceWithMarker,
            vec![Pattern::Literal("never-appears".into())],
        );
        let body = b"a perfectly innocent response body";
        let (out, o) = apply(body, &f, Some("text/plain"));
        assert!(!o.triggered);
        assert_eq!(out, body);
    }
}
