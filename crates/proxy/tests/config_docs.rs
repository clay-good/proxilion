//! Config-documentation drift gate (production-readiness.md PR-13).
//!
//! The proxy's operator-facing configuration surface lives in source as a set
//! of `env::var(...)` / `secret_env(...)` reads and a `FileConfig` struct.
//! Two authoritative documents describe it for operators:
//!
//!   * `docs/ops/config-reference.md` — every env var, default, security note.
//!   * `config/proxilion.example.toml` — every TOML field, commented template.
//!
//! These tests fail the build when the docs drift from the code, so a new
//! setting cannot ship undocumented. The check is a deterministic text scan of
//! the source tree — no reflection, no crate items needed — which is why it
//! lives as an integration test (the `proxy` crate is bin-only). The scan is
//! deliberately narrow: it matches only `env::var("NAME")` /
//! `env::var_os("NAME")` / `secret_env("NAME")` with a literal UPPER_SNAKE
//! argument, so `env::var(SOME_CONST)` / `env::var(format!(..))` (e.g. the
//! `*_FILE` variants and the test-only `PROXILION_TEST_DATABASE_URL`) are
//! correctly out of scope.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    // crates/proxy → repo root
    manifest_dir().join("..").join("..")
}

/// Recursively collect every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Extract the literal NAME from every `<prefix>NAME")` occurrence, where NAME
/// is an UPPER_SNAKE identifier. `prefix` includes the opening quote, e.g.
/// `env::var("`.
fn extract_after(haystack: &str, prefix: &str, out: &mut BTreeSet<String>) {
    let mut rest = haystack;
    while let Some(idx) = rest.find(prefix) {
        let tail = &rest[idx + prefix.len()..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        // Require a closing quote immediately after the identifier and a
        // sane shape (starts with a letter) so we don't capture partial
        // tokens or empty matches.
        let after = &tail[name.len()..];
        if after.starts_with('"') && name.starts_with(|c: char| c.is_ascii_uppercase()) {
            out.insert(name);
        }
        rest = &rest[idx + prefix.len()..];
    }
}

/// Every operator-facing env var the proxy source actually reads.
fn env_vars_read_in_source() -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(&manifest_dir().join("src"), &mut files);
    let mut vars = BTreeSet::new();
    for f in files {
        let src = fs::read_to_string(&f).unwrap_or_default();
        for prefix in ["env::var(\"", "env::var_os(\"", "secret_env(\""] {
            extract_after(&src, prefix, &mut vars);
        }
    }
    vars
}

#[test]
fn every_env_var_read_in_source_is_documented_in_config_reference() {
    let doc_path = repo_root()
        .join("docs")
        .join("ops")
        .join("config-reference.md");
    let doc = fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("config-reference.md must exist at {doc_path:?}: {e}"));

    let read = env_vars_read_in_source();
    assert!(
        !read.is_empty(),
        "scanner found no env reads — the extraction pattern likely drifted",
    );

    let undocumented: Vec<&String> = read.iter().filter(|v| !doc.contains(v.as_str())).collect();
    assert!(
        undocumented.is_empty(),
        "these env vars are read in crates/proxy/src but not documented in \
         docs/ops/config-reference.md: {undocumented:?}\n\
         Add a row for each (PR-13 keeps the reference authoritative).",
    );
}

/// Extract the `FileConfig` field names from `config.rs`.
fn file_config_fields() -> Vec<String> {
    let src = fs::read_to_string(manifest_dir().join("src").join("config.rs"))
        .expect("config.rs must be readable");
    let start = src
        .find("struct FileConfig {")
        .expect("FileConfig struct must exist");
    let body = &src[start..];
    let end = body.find('}').expect("FileConfig must close");
    let body = &body[..end];

    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            // Field lines look like `name: Option<...>,`.
            let (name, rest) = line.split_once(':')?;
            let name = name.trim();
            if rest.trim_start().starts_with("Option")
                && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                && !name.is_empty()
            {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn every_file_config_field_is_present_in_example_toml() {
    let example_path = repo_root().join("config").join("proxilion.example.toml");
    let example = fs::read_to_string(&example_path)
        .unwrap_or_else(|e| panic!("example toml must exist at {example_path:?}: {e}"));

    let fields = file_config_fields();
    assert!(
        fields.len() >= 30,
        "expected the full FileConfig field set, got {} — extraction drifted",
        fields.len(),
    );

    // A field is "shown" when some line, after stripping a leading `#` and
    // surrounding whitespace, reads `<field> = ...` (the example aligns `=`
    // with runs of spaces, so match the field token then any spaces then `=`).
    let shown = |field: &str| {
        example.lines().any(|line| {
            let line = line.trim_start().trim_start_matches('#').trim_start();
            line.strip_prefix(field)
                .map(|rest| rest.trim_start().starts_with('='))
                .unwrap_or(false)
        })
    };
    let missing: Vec<&String> = fields.iter().filter(|f| !shown(f)).collect();
    assert!(
        missing.is_empty(),
        "these FileConfig fields are not shown in config/proxilion.example.toml: \
         {missing:?}\nAdd a commented `# {{field}} = ...` line for each.",
    );
}
