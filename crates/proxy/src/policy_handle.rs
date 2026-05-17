//! Hot-reloadable policy handle (ui-less-surfaces.md §2.3).
//!
//! `PolicyHandle` is the single source of truth the adapters read on
//! every request. It wraps an `ArcSwap<Engine>` so swaps are lock-free
//! and atomic — readers either see the old engine or the new one, never
//! a partial update.
//!
//! Sources of reloads:
//!   * the operator API `POST /api/v1/policy/reload` (force re-read from disk)
//!   * the file-watcher background task (poll mtime every `WATCH_INTERVAL`)
//!   * `POST /api/v1/policy/{id}/mode` (in-memory mode flip, no disk write)
//!
//! Reload validation:
//!   * parse + compile *before* swap. Failure leaves the previous engine live.
//!   * emit `proxilion_policy_reload_success_total` or
//!     `proxilion_policy_reload_failures_total{reason}`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use policy_engine::{Engine, Mode, PolicyLoader};
use serde::Serialize;
use tracing::{info, warn};

/// Poll interval for the background watcher. ui-less-surfaces.md §2.3
/// fallback semantics: "fall back to 5s polling everywhere else."
pub const WATCH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct PolicyHandle {
    engine: Arc<ArcSwap<Engine>>,
    /// File path the engine was last loaded from. `None` when the proxy
    /// was started without `PROXILION_POLICY_PATH` (engine is built from
    /// an inline empty list and reload-from-disk is a no-op).
    source: Option<PathBuf>,
    /// Snapshot of the raw YAML — surfaced on `GET /api/v1/policy/{id}`
    /// and used by `POST /api/v1/policy/{id}/mode` to round-trip mode
    /// flips back to disk in a future iteration.
    raw_yaml: Arc<ArcSwap<String>>,
    /// Optional pluggable backend — `Some` when constructed via
    /// `with_loader`. The file-watcher path uses this to short-circuit
    /// identical reloads via `changed_since`, and a future `DbPolicyLoader`
    /// drops in here without touching adapters. qiuth-patterns.md §5.
    loader: Option<Arc<dyn PolicyLoader>>,
    /// Last successful version token from the loader. Used by the
    /// watcher to skip no-op reloads.
    last_version: Arc<ArcSwap<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReloadReport {
    pub ok: bool,
    pub source: Option<String>,
    pub policy_count: usize,
    pub error: Option<String>,
}

impl PolicyHandle {
    pub fn new(initial: Engine, source: Option<PathBuf>, raw_yaml: String) -> Self {
        Self {
            engine: Arc::new(ArcSwap::from_pointee(initial)),
            source,
            raw_yaml: Arc::new(ArcSwap::from_pointee(raw_yaml)),
            loader: None,
            last_version: Arc::new(ArcSwap::from_pointee(String::new())),
        }
    }

    /// Build a handle backed by an arbitrary [`PolicyLoader`].
    /// `initial_version` is the version token reported by the loader for
    /// the YAML the handle was built with — passed through so the
    /// watcher's first `changed_since` tick can short-circuit.
    /// qiuth-patterns.md §5.
    pub fn with_loader(
        initial: Engine,
        loader: Arc<dyn PolicyLoader>,
        raw_yaml: String,
        initial_version: String,
        source: Option<PathBuf>,
    ) -> Self {
        Self {
            engine: Arc::new(ArcSwap::from_pointee(initial)),
            source,
            raw_yaml: Arc::new(ArcSwap::from_pointee(raw_yaml)),
            loader: Some(loader),
            last_version: Arc::new(ArcSwap::from_pointee(initial_version)),
        }
    }

    pub fn loader(&self) -> Option<Arc<dyn PolicyLoader>> {
        self.loader.clone()
    }

    /// Current version token from the most recent successful loader reload.
    /// Empty string when no loader is attached.
    pub fn last_version(&self) -> Arc<String> {
        self.last_version.load_full()
    }

    /// Snapshot the current engine for evaluation. Cheap — bumps an
    /// atomic refcount, doesn't clone the engine itself.
    pub fn load(&self) -> Arc<Engine> {
        self.engine.load_full()
    }

    pub fn source(&self) -> Option<&PathBuf> {
        self.source.as_ref()
    }

    pub fn raw_yaml(&self) -> Arc<String> {
        self.raw_yaml.load_full()
    }

    /// Re-read the policy file from disk and atomically swap the engine.
    /// Validation runs before the swap; on parse failure the previous
    /// engine remains live and the failure is recorded in metrics + log.
    pub fn reload_from_disk(&self) -> ReloadReport {
        let Some(path) = self.source.as_ref() else {
            metrics::counter!(
                "proxilion_policy_reload_failures_total",
                "reason" => "no_source"
            )
            .increment(1);
            return ReloadReport {
                ok: false,
                source: None,
                policy_count: self.load().policy_count(),
                error: Some("no policy file configured".into()),
            };
        };
        let yaml = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "policy reload: read failed");
                metrics::counter!(
                    "proxilion_policy_reload_failures_total",
                    "reason" => "io_error"
                )
                .increment(1);
                return ReloadReport {
                    ok: false,
                    source: Some(path.display().to_string()),
                    policy_count: self.load().policy_count(),
                    error: Some(format!("read failed: {e}")),
                };
            }
        };
        self.swap_from_yaml(yaml, path.display().to_string())
    }

    /// Swap the engine to a YAML string the caller already has in hand.
    /// Used by `set_mode` (round-trips mutated YAML) and the file watcher.
    pub fn swap_from_yaml(&self, yaml: String, source: String) -> ReloadReport {
        self.swap_from_yaml_with_version(yaml, source, None)
    }

    /// Same as [`swap_from_yaml`], plus stores the loader's version token
    /// so the watcher's next `changed_since` call short-circuits when the
    /// source is unchanged. qiuth-patterns.md §5.
    pub fn swap_from_yaml_with_version(
        &self,
        yaml: String,
        source: String,
        version: Option<String>,
    ) -> ReloadReport {
        match Engine::new(&yaml) {
            Ok(engine) => {
                let n = engine.policy_count();
                self.engine.store(Arc::new(engine));
                self.raw_yaml.store(Arc::new(yaml));
                if let Some(v) = version {
                    self.last_version.store(Arc::new(v));
                }
                info!(source = %source, policy_count = n, "policy reloaded");
                metrics::counter!("proxilion_policy_reload_success_total").increment(1);
                ReloadReport {
                    ok: true,
                    source: Some(source),
                    policy_count: n,
                    error: None,
                }
            }
            Err(e) => {
                warn!(error = %e, source = %source, "policy reload: parse failed");
                metrics::counter!(
                    "proxilion_policy_reload_failures_total",
                    "reason" => "parse_error"
                )
                .increment(1);
                ReloadReport {
                    ok: false,
                    source: Some(source),
                    policy_count: self.load().policy_count(),
                    error: Some(format!("parse failed: {e}")),
                }
            }
        }
    }

    /// Async reload via the attached [`PolicyLoader`]. Returns the report
    /// plus the loader's new version token. Used by the watcher when a
    /// loader is attached; falls back to `reload_from_disk` otherwise.
    /// qiuth-patterns.md §5.
    pub async fn reload_via_loader(&self) -> ReloadReport {
        let Some(loader) = self.loader.as_ref() else {
            // No loader → keep prior behavior.
            return self.reload_from_disk();
        };
        match loader.load().await {
            Ok(bundle) => self.swap_from_yaml_with_version(
                bundle.yaml,
                loader.source_label(),
                Some(bundle.version),
            ),
            Err(e) => {
                warn!(error = %e, source = %loader.source_label(), "policy reload via loader failed");
                metrics::counter!(
                    "proxilion_policy_reload_failures_total",
                    "reason" => "io_error"
                )
                .increment(1);
                ReloadReport {
                    ok: false,
                    source: Some(loader.source_label()),
                    policy_count: self.load().policy_count(),
                    error: Some(format!("loader: {e}")),
                }
            }
        }
    }

    /// In-memory mode flip for a single policy. Used by
    /// `POST /api/v1/policy/{id}/mode`.
    ///
    /// Strategy (ui-less-surfaces.md §11.1, resolved 2026-05-12):
    ///
    /// 1. **Line-oriented edit** — locate the policy block by `- id: <foo>`,
    ///    then replace (or insert) the top-level `mode:` field in place.
    ///    Comments, key ordering, blank lines, and the operator's
    ///    formatting are all preserved byte-for-byte outside the one
    ///    edited line.
    ///
    /// 2. **`serde_yaml` fallback** — if the line walk can't locate a
    ///    structural anchor (e.g. the policy uses an exotic YAML form we
    ///    don't recognize), we fall back to the legacy
    ///    `serde_yaml::Value` round-trip. That path may mangle comments,
    ///    but it's correct for any well-formed YAML and only fires for
    ///    inputs the line walker rejects.
    ///
    /// In both cases the resulting YAML is validated by parsing into an
    /// `Engine` before the atomic swap; on parse failure the previous
    /// engine remains live and `SetModeError::Reload` surfaces.
    pub fn set_mode(&self, policy_id: &str, mode: Mode) -> Result<ReloadReport, SetModeError> {
        let yaml = self.raw_yaml.load_full();
        let new_yaml = match edit_mode_in_yaml(yaml.as_str(), policy_id, mode) {
            Ok(s) => s,
            Err(SetModeError::NotFound(id)) => {
                // Line walker couldn't find the policy block. Fall back
                // to the structural round-trip so genuinely missing ids
                // surface as NotFound (not silent loss).
                set_mode_via_serde(yaml.as_str(), &id, mode)?
            }
            Err(other) => return Err(other),
        };
        let report = self.swap_from_yaml(
            new_yaml,
            self.source
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(in-memory)".into()),
        );
        if !report.ok {
            return Err(SetModeError::Reload(
                report.error.clone().unwrap_or_default(),
            ));
        }
        Ok(report)
    }
}

/// Comment-preserving line-oriented `mode:` edit. Walks the YAML once,
/// finds the matching `- id: <policy_id>` block at the document's top
/// indent level, then replaces an existing top-level `mode:` line or
/// inserts one directly after the `id:` line. Returns
/// `SetModeError::NotFound` when the id isn't present at the top level.
fn edit_mode_in_yaml(yaml: &str, policy_id: &str, mode: Mode) -> Result<String, SetModeError> {
    let mode_value = match mode {
        Mode::Enforce => "enforce",
        Mode::Observe => "observe",
        Mode::Disabled => "disabled",
    };

    // Keep newlines on each line so we can rejoin byte-exact.
    let lines: Vec<&str> = yaml.split_inclusive('\n').collect();

    // Find the policy block by `<dash_indent>- id: <policy_id>`.
    let mut block_start: Option<usize> = None;
    let mut dash_indent_len = 0usize;
    let mut field_indent = String::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_eol(raw);
        let lead = leading_ws_len(line);
        let after_indent = &line[lead..];
        let Some(after_dash) = after_indent.strip_prefix("- ") else {
            continue;
        };
        let Some(id_val) = parse_id_value(after_dash) else {
            continue;
        };
        if id_val == policy_id {
            block_start = Some(i);
            dash_indent_len = lead;
            // Fields under `- id: foo` are indented by `<dash_indent>  `
            // (the dash + space width is two columns).
            field_indent = format!("{}  ", &line[..lead]);
            break;
        }
    }
    let Some(start_idx) = block_start else {
        return Err(SetModeError::NotFound(policy_id.to_string()));
    };

    // Determine the end of this policy block. The block ends at the
    // next line that starts a sibling list item (`<dash_indent>- `) or
    // at a line less-indented than the dash (a new document scope).
    // Blank lines and comments don't end the block.
    let mut block_end = lines.len();
    for (j, raw) in lines.iter().enumerate().skip(start_idx + 1) {
        let line = strip_eol(raw);
        if line.trim().is_empty() {
            continue;
        }
        let lead = leading_ws_len(line);
        let trimmed = &line[lead..];
        if lead == dash_indent_len && trimmed.starts_with('-') {
            block_end = j;
            break;
        }
        if lead < dash_indent_len && !trimmed.starts_with('#') {
            block_end = j;
            break;
        }
    }

    // Search for a top-level `mode:` field within the block. "Top-level"
    // means indented exactly at `field_indent` — guards against matching
    // `mode:` inside a nested `match:` map.
    let mut mode_line_idx: Option<usize> = None;
    for (j, raw) in lines
        .iter()
        .enumerate()
        .skip(start_idx + 1)
        .take(block_end.saturating_sub(start_idx + 1))
    {
        let line = strip_eol(raw);
        let lead = leading_ws_len(line);
        if lead != field_indent.len() {
            continue;
        }
        let rest = &line[lead..];
        if rest.starts_with("mode:")
            && rest
                .as_bytes()
                .get(5)
                .is_none_or(|b| matches!(b, b' ' | b'\t' | b'#'))
        {
            mode_line_idx = Some(j);
            break;
        }
    }

    let mut out: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();

    match mode_line_idx {
        Some(j) => {
            // Replace the value on the existing `mode:` line, preserve
            // a trailing `# comment` if present.
            let original = out[j].clone();
            let had_nl = original.ends_with('\n');
            let body = strip_eol(&original).to_string();
            let key_end = body.find("mode:").expect("scanned above") + "mode:".len();
            let prefix = &body[..key_end];
            let after = &body[key_end..];
            let comment_off = find_inline_comment(after);
            let comment_tail = match comment_off {
                Some(ci) => format!("  {}", after[ci..].trim_start()),
                None => String::new(),
            };
            let mut new_line = format!("{prefix} {mode_value}{comment_tail}");
            if had_nl {
                new_line.push('\n');
            }
            out[j] = new_line;
        }
        None => {
            // Insert a new `mode:` line directly after the `id:` line.
            // The `id:` line is `out[start_idx]`; ensure it ends in '\n'
            // so the inserted line is on its own row.
            if !out[start_idx].ends_with('\n') {
                out[start_idx].push('\n');
            }
            let inserted = format!("{field_indent}mode: {mode_value}\n");
            out.insert(start_idx + 1, inserted);
        }
    }

    Ok(out.join(""))
}

fn strip_eol(s: &str) -> &str {
    s.strip_suffix('\n').unwrap_or(s)
}

fn leading_ws_len(s: &str) -> usize {
    s.len() - s.trim_start_matches([' ', '\t']).len()
}

/// Parse `id: <value>` from a line fragment (the part after `- `). Returns
/// the unquoted scalar id, or `None` if the fragment isn't a scalar `id:`
/// declaration.
fn parse_id_value(fragment: &str) -> Option<&str> {
    let after = fragment.strip_prefix("id:")?;
    // `id:foo` is invalid YAML (no space after colon) — reject to avoid
    // matching things like `pid: foo`.
    if !after.starts_with(' ') && !after.starts_with('\t') {
        return None;
    }
    let val = after.trim_start();
    let end = find_inline_comment(val).unwrap_or(val.len());
    let val = val[..end].trim_end();
    let unquoted = val
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| val.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(val);
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted)
    }
}

/// Position of an inline `#` comment start within `s`, requiring the
/// `#` to be preceded by whitespace (so URLs etc. don't trigger).
fn find_inline_comment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return Some(i);
        }
    }
    None
}

/// Legacy `serde_yaml::Value` round-trip. Used as a fallback when the
/// line-oriented edit can't locate a structural anchor — covers exotic
/// YAML shapes we don't recognize line-by-line, at the cost of
/// reformatting / comment loss.
fn set_mode_via_serde(yaml: &str, policy_id: &str, mode: Mode) -> Result<String, SetModeError> {
    let mut docs: Vec<serde_yaml::Value> =
        serde_yaml::from_str(yaml).map_err(|e| SetModeError::Parse(e.to_string()))?;
    let mut found = false;
    for d in docs.iter_mut() {
        let Some(map) = d.as_mapping_mut() else {
            continue;
        };
        let id_key = serde_yaml::Value::String("id".into());
        if map.get(&id_key).and_then(|v| v.as_str()) == Some(policy_id) {
            map.insert(
                serde_yaml::Value::String("mode".into()),
                serde_yaml::Value::String(
                    match mode {
                        Mode::Enforce => "enforce",
                        Mode::Observe => "observe",
                        Mode::Disabled => "disabled",
                    }
                    .to_string(),
                ),
            );
            found = true;
            break;
        }
    }
    if !found {
        return Err(SetModeError::NotFound(policy_id.to_string()));
    }
    serde_yaml::to_string(&docs).map_err(|e| SetModeError::Parse(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum SetModeError {
    #[error("policy `{0}` not found")]
    NotFound(String),
    #[error("yaml parse: {0}")]
    Parse(String),
    #[error("reload after mutation: {0}")]
    Reload(String),
}

/// Background poll loop. Watches the policy file's mtime; reloads when
/// it changes. Spawned by `server::run` when `PROXILION_POLICY_PATH` is
/// set. ui-less-surfaces.md §2.3 — "fall back to 5s polling everywhere
/// else" (we cross-compile to Linux, macOS, and BSD targets, so
/// platform-specific watchers add complexity without buying much).
pub async fn spawn_watcher(handle: PolicyHandle) {
    // Loader-aware path (qiuth-patterns.md §5): if a loader is attached,
    // poll its `changed_since` and reload via the loader so backends like
    // a future `DbPolicyLoader` plug in transparently.
    if let Some(loader) = handle.loader() {
        let label = loader.source_label();
        info!(source = %label, interval_seconds = WATCH_INTERVAL.as_secs(), "policy loader watcher started");
        loop {
            tokio::time::sleep(WATCH_INTERVAL).await;
            let current = handle.last_version();
            match loader.changed_since(current.as_str()).await {
                Ok(Some(_new_version)) => {
                    info!(source = %label, "policy source changed; reloading via loader");
                    let _ = handle.reload_via_loader().await;
                    // Version is updated inside `swap_from_yaml_with_version`
                    // on success; on failure we leave it so the next tick retries.
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(source = %label, error = %e, "policy loader version check failed");
                }
            }
        }
    }

    // Legacy file-mtime path (no loader). Kept for back-compat with the
    // existing construction path in `server.rs`.
    let Some(path) = handle.source().cloned() else {
        return;
    };
    let mut last_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    info!(path = %path.display(), interval_seconds = WATCH_INTERVAL.as_secs(), "policy file watcher started");
    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;
        match std::fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => {
                if Some(t) != last_mtime {
                    info!(path = %path.display(), "policy file changed; reloading");
                    let r = handle.reload_from_disk();
                    if r.ok {
                        last_mtime = Some(t);
                    }
                    // If reload failed, leave last_mtime as-is so the next
                    // tick retries.
                }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "policy file metadata read failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with(yaml: &str) -> Engine {
        Engine::new(yaml).expect("test policy parses")
    }

    #[test]
    fn load_returns_current_engine() {
        let yaml = "[]";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        assert_eq!(h.load().policy_count(), 0);
    }

    #[test]
    fn swap_from_yaml_updates_engine_atomically() {
        let h = PolicyHandle::new(engine_with("[]"), None, "[]".into());
        let report = h.swap_from_yaml(
            "- id: p1\n  vendor: google\n  action: drive.files.get\n  decision: allow\n  required_ops: []\n".into(),
            "test".into(),
        );
        assert!(report.ok, "{report:?}");
        assert_eq!(report.policy_count, 1);
        assert_eq!(h.load().policy_count(), 1);
    }

    #[test]
    fn swap_with_bad_yaml_keeps_previous_engine() {
        let h = PolicyHandle::new(engine_with("[]"), None, "[]".into());
        let report = h.swap_from_yaml("this is :: not yaml ::\n  - [".into(), "test".into());
        assert!(!report.ok);
        assert!(report.error.is_some());
        // Engine still 0 policies (the old one).
        assert_eq!(h.load().policy_count(), 0);
    }

    #[test]
    fn set_mode_flips_policy_to_observe() {
        let yaml = r#"- id: gmail-x
  vendor: google
  action: gmail.messages.send
  decision: block
  required_ops: []
"#;
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        let report = h.set_mode("gmail-x", Mode::Observe).expect("set_mode ok");
        assert!(report.ok);
        // After the flip the new engine must report mode=Observe for this
        // policy. Build a request context that would have matched.
        let ctx = policy_engine::RequestContext {
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            user: policy_engine::UserCtx {
                email: "alice@acme.com".into(),
                groups: vec![],
            },
            path: Default::default(),
            body: Default::default(),
            headers: Default::default(),
            customer_domain: "acme.com".into(),
        };
        let out = h.load().evaluate(&ctx).unwrap();
        assert_eq!(out.mode, Mode::Observe);
        assert_eq!(out.observe_would_have.as_deref(), Some("observe_block"));
    }

    #[test]
    fn set_mode_returns_not_found() {
        let h = PolicyHandle::new(engine_with("[]"), None, "[]".into());
        let err = h.set_mode("nope", Mode::Observe).unwrap_err();
        assert!(matches!(err, SetModeError::NotFound(_)));
    }

    /// ui-less-surfaces.md §11.1 — comments, blank lines, key ordering,
    /// and the trailing-comment on the edited `mode:` line all survive
    /// a `set_mode` round-trip.
    #[test]
    fn set_mode_preserves_comments_and_ordering() {
        let yaml = "\
# top-of-file commentary about the bundle
# spanning multiple lines

- id: alpha-policy
  vendor: google
  action: drive.files.get
  # mode is currently audit-only while we tune the regex set
  mode: enforce   # do-not-touch: owned by secops
  decision: allow
  required_ops:
    - \"drive:read:file/${path.id}\"
  pic_mode: audit

# next policy gates external gmail sends
- id: beta-policy
  vendor: google
  action: gmail.messages.send
  decision: block
  required_ops: []
  pic_mode: runtime-gate
";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        let report = h
            .set_mode("alpha-policy", Mode::Observe)
            .expect("set_mode ok");
        assert!(report.ok);

        let new_yaml = h.raw_yaml();
        // Header comments survive.
        assert!(new_yaml.contains("# top-of-file commentary about the bundle"));
        assert!(new_yaml.contains("# spanning multiple lines"));
        // The block-internal comment on the line above `mode:` survives.
        assert!(new_yaml.contains("# mode is currently audit-only while we tune the regex set"));
        // The trailing comment on the `mode:` line itself survives.
        assert!(new_yaml.contains("mode: observe"));
        assert!(new_yaml.contains("# do-not-touch: owned by secops"));
        // The next-policy comment + ordering survive.
        assert!(new_yaml.contains("# next policy gates external gmail sends"));
        // beta-policy is untouched.
        assert!(new_yaml.contains("- id: beta-policy"));
        assert!(
            !new_yaml.contains("mode: enforce"),
            "old value should be gone"
        );

        // The actual engine state agrees — alpha is now Observe.
        let ctx = policy_engine::RequestContext {
            vendor: "google".into(),
            action: "drive.files.get".into(),
            user: policy_engine::UserCtx {
                email: "alice@acme.com".into(),
                groups: vec![],
            },
            path: {
                let mut m = std::collections::HashMap::new();
                m.insert("id".into(), "f1".into());
                m
            },
            body: Default::default(),
            headers: Default::default(),
            customer_domain: "acme.com".into(),
        };
        let out = h.load().evaluate(&ctx).unwrap();
        assert_eq!(out.mode, Mode::Observe);
    }

    /// When the policy has no `mode:` field yet, `set_mode` inserts one
    /// right after `id:` rather than appending at the block end. This
    /// keeps the field near the policy's identity, which is the
    /// convention in the existing `config/policy.yaml`.
    #[test]
    fn set_mode_inserts_when_field_absent() {
        let yaml = "\
- id: needs-mode
  vendor: google
  action: drive.files.get
  decision: allow
  required_ops: []
  pic_mode: audit
";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        h.set_mode("needs-mode", Mode::Disabled)
            .expect("set_mode ok");
        let new_yaml = h.raw_yaml();
        let id_pos = new_yaml.find("- id: needs-mode").unwrap();
        let mode_pos = new_yaml.find("mode: disabled").unwrap();
        let vendor_pos = new_yaml.find("vendor: google").unwrap();
        assert!(
            id_pos < mode_pos && mode_pos < vendor_pos,
            "mode should land between id and vendor"
        );
    }

    /// A nested `mode:` (e.g. inside `match:`) must not be mistaken for
    /// the top-level policy field. The line walker keys off indent
    /// depth; this exercises that.
    #[test]
    fn set_mode_does_not_match_nested_mode_key() {
        let yaml = "\
- id: nested
  vendor: google
  action: drive.files.get
  match:
    headers.x-mode:
      equals: stealth
  decision: allow
  required_ops: []
  pic_mode: audit
";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        h.set_mode("nested", Mode::Observe).expect("set_mode ok");
        let new_yaml = h.raw_yaml();
        // The synthetic top-level `mode:` was inserted (not the nested
        // `headers.x-mode:` mutated).
        assert!(new_yaml.contains("mode: observe"));
        assert!(new_yaml.contains("headers.x-mode:"));
        assert!(new_yaml.contains("equals: stealth"));
    }

    #[test]
    fn edit_mode_in_yaml_not_found_falls_through_to_serde() {
        // The serde fallback also won't find a missing id; the public
        // API surfaces `NotFound` either way. This guards against the
        // line walker silently passing `Err(NotFound)` up without the
        // fallback path being exercised.
        let yaml = "[]\n";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        let err = h.set_mode("ghost", Mode::Observe).unwrap_err();
        assert!(matches!(err, SetModeError::NotFound(ref id) if id == "ghost"));
    }

    #[tokio::test]
    async fn reload_via_loader_swaps_engine_and_bumps_version() {
        use policy_engine::StaticPolicyLoader;
        let yaml0 = "[]";
        let loader = Arc::new(StaticPolicyLoader::new(yaml0).with_label("test-loader"));
        let initial = engine_with(yaml0);
        let v0 = loader.load().await.unwrap().version;
        let h = PolicyHandle::with_loader(initial, loader.clone(), yaml0.into(), v0.clone(), None);

        // Mutate the loader's YAML and reload through the handle.
        loader.set_yaml(
            "- id: viaLoader\n  vendor: google\n  action: drive.files.get\n  decision: allow\n  required_ops: []\n",
        );
        let report = h.reload_via_loader().await;
        assert!(report.ok, "{report:?}");
        assert_eq!(report.policy_count, 1);
        assert_eq!(h.load().policy_count(), 1);

        // Version token advanced.
        assert_ne!(h.last_version().as_str(), v0.as_str());
    }

    #[tokio::test]
    async fn reload_via_loader_keeps_prior_engine_on_bad_yaml() {
        use policy_engine::StaticPolicyLoader;
        let yaml0 = "[]";
        let loader = Arc::new(StaticPolicyLoader::new(yaml0));
        let initial = engine_with(yaml0);
        let v0 = loader.load().await.unwrap().version;
        let h = PolicyHandle::with_loader(initial, loader.clone(), yaml0.into(), v0, None);

        loader.set_yaml("this is :: not yaml ::\n  - [");
        let report = h.reload_via_loader().await;
        assert!(!report.ok);
        // Old engine still live.
        assert_eq!(h.load().policy_count(), 0);
    }

    #[test]
    fn reload_from_disk_with_no_source_returns_error() {
        let h = PolicyHandle::new(engine_with("[]"), None, "[]".into());
        let r = h.reload_from_disk();
        assert!(!r.ok);
        assert!(r.error.as_deref().unwrap().contains("no policy file"));
    }

    // ──────────────────────────────────────────────────────────────────
    // Pure-helper coverage for the private YAML parser the `set_mode`
    // line-walker delegates to. These were only exercised end-to-end
    // before — pinning them directly keeps a future refactor of
    // `edit_mode_in_yaml` from silently shifting behaviour on the
    // boundary cases the public tests don't reach.
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn strip_eol_removes_trailing_newline_only_when_present() {
        // A naked-string (no trailing '\n') round-trips unchanged — the
        // line walker uses `split_inclusive('\n')` which leaves the last
        // line newline-less, and the rewrite must rejoin byte-exact.
        assert_eq!(strip_eol("abc\n"), "abc");
        assert_eq!(strip_eol("abc"), "abc");
        assert_eq!(strip_eol(""), "");
        // Carriage-return is NOT stripped (CRLF inputs aren't a supported
        // shape for policy YAML; the line walker would mis-align indent
        // calculations if we silently dropped the '\r').
        assert_eq!(strip_eol("abc\r\n"), "abc\r");
    }

    #[test]
    fn leading_ws_len_counts_spaces_and_tabs_mixed() {
        // The `field_indent` computation depends on a byte-accurate count
        // (mixed-tab YAML survives intact because the rewrite preserves
        // the original lead bytes — but the length must match the source).
        assert_eq!(leading_ws_len(""), 0);
        assert_eq!(leading_ws_len("abc"), 0);
        assert_eq!(leading_ws_len("  abc"), 2);
        assert_eq!(leading_ws_len("\t\tabc"), 2);
        assert_eq!(leading_ws_len(" \t abc"), 3);
        // Non-leading whitespace is not counted.
        assert_eq!(leading_ws_len("ab cd"), 0);
    }

    #[test]
    fn parse_id_value_extracts_bare_and_quoted_scalars() {
        assert_eq!(parse_id_value("id: alpha"), Some("alpha"));
        // Trailing whitespace trimmed.
        assert_eq!(parse_id_value("id: alpha   "), Some("alpha"));
        // Double-quoted scalar — quotes stripped.
        assert_eq!(
            parse_id_value(r#"id: "with-spaces and stuff""#),
            Some("with-spaces and stuff")
        );
        // Single-quoted scalar — quotes stripped.
        assert_eq!(parse_id_value("id: 'beta'"), Some("beta"));
    }

    #[test]
    fn parse_id_value_rejects_missing_space_after_colon_to_avoid_pid_match() {
        // `pid: foo` lines must not match `id:` — the colon-without-space
        // gate is what stops the line walker hijacking sibling fields.
        assert_eq!(parse_id_value("id:foo"), None);
        // `pid: foo` doesn't even start with `id:` so it's caught earlier,
        // but we pin the dense form here as a regression sentinel.
        assert_eq!(parse_id_value("pid: foo"), None);
        // A tab between colon and value is accepted (YAML allows it).
        assert_eq!(parse_id_value("id:\tx"), Some("x"));
    }

    #[test]
    fn parse_id_value_returns_none_for_empty_or_comment_only_value() {
        // Empty value after `id:` is not a valid policy block anchor.
        assert_eq!(parse_id_value("id: "), None);
        // Quoted-empty: stripped quotes leave empty string → None.
        assert_eq!(parse_id_value(r#"id: """#), None);
        // Value composed entirely of a trailing comment after the space is
        // also empty after stripping (the comment-finder fires on the
        // post-space byte).
        assert_eq!(parse_id_value("id:  # placeholder"), None);
    }

    #[test]
    fn find_inline_comment_requires_preceding_whitespace() {
        // The `#` must be at column 0 OR have a whitespace byte before it.
        // This stops URLs (e.g. `https://foo#frag`) from being mistaken for
        // inline comments — important because policy `match:` rules carry
        // user-supplied strings that may include `#`.
        assert_eq!(find_inline_comment("abc # comment"), Some(4));
        assert_eq!(find_inline_comment("# leading"), Some(0));
        assert_eq!(find_inline_comment("https://x#frag"), None);
        assert_eq!(find_inline_comment("nohash"), None);
        // Tab before `#` also counts as whitespace.
        assert_eq!(find_inline_comment("abc\t#x"), Some(4));
    }

    #[test]
    fn set_mode_error_display_strings_are_stable_for_log_filters() {
        // Each variant emits a distinct operator-facing prefix the
        // troubleshooting docs page keys on; pin both prefix and that the
        // carried payload (id / parse message / reload reason) appears in
        // the rendered text.
        assert_eq!(
            SetModeError::NotFound("alpha".into()).to_string(),
            "policy `alpha` not found"
        );
        assert_eq!(
            SetModeError::Parse("scanner error at line 7".into()).to_string(),
            "yaml parse: scanner error at line 7"
        );
        assert_eq!(
            SetModeError::Reload("schema mismatch on key X".into()).to_string(),
            "reload after mutation: schema mismatch on key X"
        );
    }

    #[test]
    fn set_mode_via_serde_fallback_round_trips_when_yaml_is_a_flow_mapping() {
        // The line-oriented walker only recognizes block-style YAML; an
        // operator who hand-edits to flow style would otherwise hit
        // `NotFound` even though the policy exists. The serde fallback
        // path catches this — pin it here on a flow-mapping input where
        // the line walker wouldn't have found the anchor.
        let yaml = "- {id: gamma, vendor: google, action: drive.files.get, decision: allow, required_ops: []}\n";
        let out = set_mode_via_serde(yaml, "gamma", Mode::Observe).expect("serde fallback ok");
        // The output is reformatted (comment loss is documented), but the
        // policy must now carry `mode: observe`.
        assert!(out.contains("mode: observe"), "rewritten: {out}");
        assert!(out.contains("id: gamma"));
    }
}
