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
    fn policy_handle_and_reload_report_and_set_mode_error_send_sync_static() {
        // `PolicyHandle` is the single source of truth read by every
        // adapter on every request — held in AppState and cloned per
        // request scope. `ReloadReport` flows through `tokio::spawn`-ed
        // watcher tasks. `SetModeError` flows through `Result` chains
        // across `.await` points in the API handler. All three MUST be
        // Send+Sync+'static — a refactor adding an `Rc<...>` field on
        // any one would break Sync at the AppState wire site rather
        // than as a far-removed trait-bound error. Pin all three at
        // this file boundary.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PolicyHandle>();
        require_send_sync_static::<ReloadReport>();
        require_send_sync_static::<SetModeError>();
    }

    #[test]
    fn reload_report_serializes_with_exactly_four_known_keys() {
        // `ReloadReport` is serialized into the operator-facing
        // `/api/v1/policy/reload` response body — the dashboard
        // surfaces all 4 fields by name (`ok`, `source`,
        // `policy_count`, `error`). The JSON object MUST carry
        // EXACTLY 4 keys. A refactor that elided one (e.g. adding
        // `skip_serializing_if = "Option::is_none"` to `error` "for
        // clean wire on success") would silently drop operator-
        // visible state from the reload toast; an addition would
        // widen the wire shape. Pin both axes — count AND each name —
        // across BOTH polarities (success: ok=true error=None +
        // failure: ok=false error=Some).
        for r in [
            ReloadReport {
                ok: true,
                source: Some("path".into()),
                policy_count: 3,
                error: None,
            },
            ReloadReport {
                ok: false,
                source: None,
                policy_count: 0,
                error: Some("yaml parse error".into()),
            },
        ] {
            let v = serde_json::to_value(&r).unwrap();
            let obj = v.as_object().expect("must be JSON object");
            assert_eq!(obj.len(), 4, "field count drift: {obj:?}");
            for k in ["ok", "source", "policy_count", "error"] {
                assert!(obj.contains_key(k), "missing {k}: {obj:?}");
            }
        }
    }

    #[test]
    fn watch_interval_constant_is_five_seconds_per_documented_fallback_semantics() {
        // The module docstring + ui-less-surfaces.md §2.3 commit to
        // 5-second polling as the watcher's fallback cadence. A refactor
        // to 1s "for snappier reload" would silently 5x the IO load on
        // every install; a refactor to 30s "for hygiene" would silently
        // delay every operator-visible reload by half a minute. Pin
        // the exact `Duration::from_secs(5)` value AND the type via
        // require_duration so a refactor to `u64` raw seconds "for
        // arithmetic ergonomics" surfaces as a type-coercion failure.
        fn require_duration(_: Duration) {}
        require_duration(WATCH_INTERVAL);
        assert_eq!(WATCH_INTERVAL, Duration::from_secs(5));
        assert_eq!(WATCH_INTERVAL.as_secs(), 5);
        assert_eq!(WATCH_INTERVAL.subsec_nanos(), 0);
    }

    #[test]
    fn policy_handle_clone_shares_inner_arc_swap_engine_via_load() {
        // `PolicyHandle` derives `Clone` — the Arc<ArcSwap<Engine>>
        // field is cloned by Arc::clone (cheap ref-count bump) so
        // BOTH clones see the same underlying engine. A refactor that
        // accidentally deep-copied the ArcSwap "for engine isolation
        // per request scope" would silently break the live-reload
        // contract — operators would issue a reload, the clone in
        // each request scope would never see the new engine. Pin via
        // Arc::ptr_eq on the loaded engines: both clones must produce
        // pointer-equal Arc<Engine> handles on `load()`.
        let yaml = "[]";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        let clone = h.clone();
        let a = h.load();
        let b = clone.load();
        assert!(
            Arc::ptr_eq(&a, &b),
            "Clone must share inner Engine via Arc — broke if deep-copied",
        );
    }

    #[test]
    fn raw_yaml_accessor_returns_owned_arc_string_for_cross_thread_sharing() {
        // `raw_yaml()` returns `Arc<String>` (NOT `&str` or `&String`)
        // — the operator API endpoint `/api/v1/policy/{id}` reads it
        // and holds it across the `.await` for the response
        // serialize. The returned Arc clones at zero copy (refcount
        // bump). A refactor to `&str` "for zero-alloc reads" would
        // surface as a borrow-checker error at the API call site
        // (lifetime tied to the handle, can't be held across .await).
        // Pin the Arc<String> return type via a helper.
        fn require_arc_string(_: Arc<String>) {}
        let yaml = "- id: x\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n";
        let h = PolicyHandle::new(engine_with(yaml), None, yaml.into());
        let got = h.raw_yaml();
        require_arc_string(got.clone());
        // Sanity that the content survives the round-trip.
        assert_eq!(&*got, yaml);
    }

    #[test]
    fn set_mode_error_debug_carries_variant_names_for_grep_bucketing() {
        // `SetModeError` is the operator-facing error for the
        // `/api/v1/policy/{id}/mode` endpoint — operators grep
        // tracing log lines by variant name to bucket NotFound
        // (operator typo on policy id) vs Parse (YAML hand-edit
        // damaged the file) vs Reload (mutation applied but the
        // resulting engine refused to compile). A hand-rolled
        // `impl Debug` that hid variant names "to compact" the line
        // would break every operator bucket. Symmetric to the
        // AppError + OAuthError + ApiError variant-name Debug pins.
        for (variant, name) in [
            (SetModeError::NotFound("p".into()), "NotFound"),
            (SetModeError::Parse("scanner".into()), "Parse"),
            (SetModeError::Reload("schema".into()), "Reload"),
        ] {
            let s = format!("{:?}", variant);
            assert!(s.contains(name), "expected `{name}` in Debug, got: {s}");
        }
    }

    // ─── round 211 (2026-05-21): pure-helper purity + ownership pins ───

    #[test]
    fn parse_id_value_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `parse_id_value` is on the YAML line-walker hot path inside
        // `edit_mode_in_yaml` — called once per `- id: …` line during
        // every `set_mode` invocation. A refactor that introduced a
        // thread-local LRU keyed on the input slice's `as_ptr()` "for
        // hot-path perf" would silently fork outputs on
        // equal-content-different-allocation inputs and break the
        // editor's per-line idempotence contract. Pin 50 calls
        // byte-equal on a representative quoted-scalar input.
        // Symmetric to the audit_body redact-helper + slack
        // parse_button_value + oauth/bridge infer_idp RT pins
        // extended to this sibling line-scanner helper.
        let input = "id: \"alpha-policy\"  # comment";
        let baseline = parse_id_value(input).map(|s| s.to_string());
        for i in 0..50 {
            let again = parse_id_value(input).map(|s| s.to_string());
            assert_eq!(
                again, baseline,
                "iteration {i}: parse_id_value must be referentially transparent",
            );
        }
    }

    #[test]
    fn parse_id_value_return_type_is_borrowed_str_view_into_input_for_zero_alloc_yaml_scan() {
        // `parse_id_value` returns `Option<&str>` — the returned slice
        // is a borrowed view into the caller's `&str` argument so the
        // line-walker can compare ids without allocating one `String`
        // per line scanned. A refactor to `Option<String>` "for owned
        // returns symmetric with `find_inline_comment`" would heap-
        // allocate per line and silently regress the policy-reload
        // hot path. Pin via pointer-equality between the input slice
        // and the returned slice's data pointer. Symmetric to round
        // 207's `slack_notifier_field_types_pinned_for_cross_await_post_contract`
        // pin (borrowed-view accessor) extended to this YAML helper.
        let input = "id: alpha";
        let parsed = parse_id_value(input).expect("matches");
        // The unquoted-scalar arm returns a slice into the input.
        let input_base = input.as_ptr() as usize;
        let parsed_base = parsed.as_ptr() as usize;
        assert!(
            parsed_base >= input_base && parsed_base < input_base + input.len(),
            "parse_id_value must return a borrowed slice into the input, got distinct allocation",
        );
        assert_eq!(parsed, "alpha");
    }

    #[test]
    fn find_inline_comment_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `find_inline_comment` is called from `parse_id_value` on every
        // matched `id:` line — equal calls must yield equal outputs. A
        // refactor that introduced a counter-mixin "for fairness across
        // multiple `#`s on the same line" (round-robin returning a
        // different `#` index per call) would silently fork the
        // comment-stripping seam between two consecutive set_mode
        // invocations. Pin 50 calls byte-equal here. Symmetric to the
        // parse_id_value RT pin above.
        let input = "alpha-policy  # comment text";
        let baseline = find_inline_comment(input);
        for i in 0..50 {
            let again = find_inline_comment(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: find_inline_comment must be referentially transparent",
            );
        }
    }

    #[test]
    fn find_inline_comment_return_type_is_option_usize_not_signed_for_string_slice_indexing() {
        // `find_inline_comment` returns `Option<usize>` — the unsigned
        // index is what `parse_id_value`'s `&val[..end]` slice operation
        // requires (a signed return would need a cast at every call
        // site, opening room for `-1`-sentinel drift). Pin the type
        // via `require_option_usize`. Symmetric to round 199's
        // `BurstConfig 3 fields threshold usize + window Duration +
        // flush_interval Duration` numeric-type pin extended to this
        // sibling helper.
        fn require_option_usize(_: &Option<usize>) {}
        let out = find_inline_comment("alpha  # c");
        require_option_usize(&out);
        // Sanity — the function found the `#` at index 7 (after the
        // two spaces).
        assert_eq!(out, Some(7));
    }

    #[test]
    fn set_mode_error_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // `SetModeError` has exactly 3 variants today (NotFound / Parse /
        // Reload) — operator log filters bucket on these arm names via
        // the round-1037 `Debug` carries-variant-name pin. A refactor
        // that landed a fourth variant (e.g. a `Schema` arm for a
        // future strict-schema validator) would silently introduce a
        // fourth dimension the dashboard's "set_mode error reason"
        // panel wasn't sized for. Pin via exhaustive-match arm names so
        // any new variant forces a conscious panel + filter update.
        // Symmetric to round 194's audit_body_mode variant-count + round
        // 208's VerifierError 8-variant + round 207's SlackAction
        // 3-variant exhaustive-match pins extended to this sibling
        // operator-facing error enum.
        fn arm_name(e: &SetModeError) -> &'static str {
            match e {
                SetModeError::NotFound(_) => "NotFound",
                SetModeError::Parse(_) => "Parse",
                SetModeError::Reload(_) => "Reload",
            }
        }
        let three: Vec<SetModeError> = vec![
            SetModeError::NotFound("x".into()),
            SetModeError::Parse("y".into()),
            SetModeError::Reload("z".into()),
        ];
        let names: std::collections::HashSet<&'static str> = three.iter().map(arm_name).collect();
        assert_eq!(names.len(), 3, "3 distinct leaf-variant names walked");
        assert_eq!(arm_name(&SetModeError::NotFound("a".into())), "NotFound");
        assert_eq!(arm_name(&SetModeError::Parse("b".into())), "Parse");
        assert_eq!(arm_name(&SetModeError::Reload("c".into())), "Reload");
    }

    #[test]
    fn edit_mode_in_yaml_return_type_is_result_owned_string_for_cross_thread_arc_wrap() {
        // `edit_mode_in_yaml` returns `Result<String, SetModeError>` —
        // the owned `String` is required because the caller
        // (`PolicyHandle::set_mode`) wraps it in `Arc::new(new_yaml)`
        // for cross-thread sharing through the `ArcSwap<String>`. A
        // refactor to `Result<Cow<'a, str>, _>` "for zero-alloc on the
        // no-op path" would introduce a lifetime parameter that the
        // surrounding `Arc::new(...)` ownership transfer can't satisfy,
        // AND foreclose the documented happy-path mutation contract.
        // Pin via require_owned_string. Symmetric to round 206's
        // `apply_return_type_is_tuple_vec_u8_and_filter_outcome_owned_by_value_...`
        // pin extended to this sibling editor helper.
        fn require_owned_string(_: &String) {}
        let yaml = "- id: alpha\n  vendor: google\n  action: drive.files.get\n  mode: enforce\n  decision: allow\n  required_ops: []\n";
        let out = edit_mode_in_yaml(yaml, "alpha", Mode::Observe).expect("edit ok");
        require_owned_string(&out);
        assert!(out.contains("mode: observe"));
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

    // ─── round 248 (2026-05-22): PolicyHandle + ReloadReport field counts,
    // load + source fn-pointer witnesses, WATCH_INTERVAL Duration type pin,
    // ReloadReport.policy_count usize pin ───

    #[test]
    fn policy_handle_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest_pattern()
    {
        // `PolicyHandle { engine, source, raw_yaml, loader, last_version }` —
        // exactly 5 fields. A 6th field landing (e.g.
        // `reload_count: Arc<AtomicU64>` for per-handle reload-frequency
        // observability OR `last_reloaded_at: Arc<ArcSwap<DateTime<Utc>>>`
        // for staleness alerting) without matching `new()` AND
        // `with_loader()` constructor wiring would silently zero-
        // initialize on every handle construction — and the
        // file-watcher's reload loop would never update the new field.
        // The exhaustive destructure with no `..` rest pattern forces a
        // 6th field to update this site in lockstep with BOTH
        // constructors. Symmetric to round-243's
        // `auth_state_field_count_pinned_at_exactly_ten_via_exhaustive_destructure_no_rest_pattern`
        // extended to this sibling hot-reload-state wrapper.
        let handle = PolicyHandle::new(engine_with(""), None, String::new());
        let PolicyHandle {
            engine: _,
            source: _,
            raw_yaml: _,
            loader: _,
            last_version: _,
        } = handle;
    }

    #[test]
    fn reload_report_field_count_pinned_at_exactly_four_via_exhaustive_destructure_no_rest_pattern()
    {
        // `ReloadReport { ok, source, policy_count, error }` — exactly
        // 4 fields. A 5th field landing (e.g. `duration_ms: u64` for
        // reload-latency observability OR `previous_policy_count: usize`
        // for delta-reporting on the dashboard) without matching
        // `reload_from_disk()` AND `swap_from_yaml()` Ok/Err arms would
        // silently drop the new field on every reload path — and the
        // existing `reload_report_serializes_with_exactly_four_known_keys`
        // pin would surface only if a 5th key landed on the wire
        // through serde, NOT if a `#[serde(skip)]` attribute was added
        // alongside the new field. The exhaustive destructure with no
        // `..` rest pattern pins the STRUCT count (not the JSON-key
        // count) so both axes move in lockstep. Symmetric to round-240's
        // `blocked_notification_field_count_pinned_at_exactly_sixteen_via_exhaustive_destructure_no_rest`
        // extended to this sibling operator-facing reload-status struct.
        let r = ReloadReport {
            ok: true,
            source: None,
            policy_count: 0,
            error: None,
        };
        let ReloadReport {
            ok: _,
            source: _,
            policy_count: _,
            error: _,
        } = r;
    }

    #[test]
    fn policy_handle_load_return_type_is_arc_engine_via_fn_pointer_witness_for_atomic_swap_share() {
        // `PolicyHandle::load(&self) -> Arc<Engine>` — returns an
        // Arc-shared Engine snapshot via `ArcSwap::load_full()`. The
        // adapter call sites (every request's policy-evaluation path)
        // depend on the Arc shape so multiple in-flight requests can
        // hold disjoint snapshots while a reload swaps in a new engine
        // mid-flight. A refactor to `&Engine` "for zero-alloc per
        // adapter call" would tie the borrow lifetime to the handle
        // — and reloads would block until every borrow drained, breaking
        // the atomic-swap contract that ArcSwap exists to provide.
        // Pin via fn-pointer witness so a return-type drift surfaces
        // at this file rather than at the adapter site with an opaque
        // lifetime error. Symmetric to round-241's
        // `broadcasting_action_stream_subscribe_return_type_is_broadcast_receiver_via_fn_pointer_witness`
        // extended to this sibling hot-reload accessor.
        let _f: fn(&PolicyHandle) -> Arc<Engine> = PolicyHandle::load;
    }

    #[test]
    fn policy_handle_source_return_type_is_option_borrowed_pathbuf_via_fn_pointer_witness() {
        // `PolicyHandle::source(&self) -> Option<&PathBuf>` — returns
        // a borrowed view into the handle's stored path. The
        // file-watcher loop calls `source()` on every tick to decide
        // whether to poll the filesystem; the BORROWED view is
        // load-bearing for the zero-alloc-per-tick contract. A
        // refactor to `Option<PathBuf>` "for ergonomic ownership at
        // the call site" would force a `PathBuf::clone()` per
        // watcher tick (one syscall + one allocation per 5-second
        // interval × N handles in a multi-tenant fork), and a
        // refactor to `Option<String>` "for serde-friendly source
        // strings" would foreclose the `PathBuf::display()` lossy-
        // unicode-fallback formatter the operator-facing log uses.
        // Pin via fn-pointer witness with explicit `for<'a>` lifetime
        // so a borrow-to-owned refactor surfaces at this file.
        // Symmetric to round-246's
        // `bearer_as_str_signature_self_borrow_returns_str_borrow_via_fn_pointer_witness`
        // extended to this sibling accessor.
        let _f: for<'a> fn(&'a PolicyHandle) -> Option<&'a PathBuf> = PolicyHandle::source;
    }

    #[test]
    fn watch_interval_constant_type_pinned_duration_via_require_duration_for_tokio_sleep_compat() {
        // `WATCH_INTERVAL: Duration = Duration::from_secs(5)` — the
        // file-watcher loop calls `tokio::time::sleep(WATCH_INTERVAL)`
        // on every tick; the `tokio::time::sleep` signature is
        // `fn sleep(duration: Duration) -> Sleep` (NOT `u64` seconds).
        // The existing `watch_interval_constant_is_five_seconds_per_documented_fallback_semantics`
        // pin walks the VALUE (5 seconds) via `as_secs() == 5`; pin the
        // TYPE via `require_duration` so a refactor to `u64` "for
        // operator-facing config-file integer surface" would force a
        // cast at every `sleep(...)` site AND would change the
        // overflow domain on multiplication (e.g. `WATCH_INTERVAL * 2`
        // for an exponential backoff refactor would overflow u64
        // silently above ~580 years vs Duration's saturating ops).
        // Symmetric to round-242's
        // `cached_pca_hop_field_pinned_i32_via_require_for_postgres_int4_signed_domain`
        // extended to this sibling tokio-sleep-typed constant.
        fn require_duration(_: Duration) {}
        require_duration(WATCH_INTERVAL);
    }

    #[test]
    fn reload_report_policy_count_field_pinned_usize_via_require_for_vec_len_dashboard_compat() {
        // `ReloadReport.policy_count: usize` — matches the
        // `Engine::policy_count()` return shape (which is the policy
        // Vec's `.len()`). The operator dashboard renders this as the
        // post-reload policy total. A refactor to `u32` "for SQL int4
        // alignment if the report ever lands in audit_events" would
        // force a `as u32` cast at every `Engine::policy_count`
        // assignment AND would silently saturate at 2^32 policies (no
        // production install gets near that, but the type contract is
        // the boundary). Pin via require_usize. The `error: Option<String>`
        // sibling field is symmetrically pinned via the field-types
        // tests round-219. Symmetric to round-244's
        // `scenario_quarantined_count_field_is_usize_type_for_vec_len_compat`
        // extended to this sibling reload-report counter field.
        fn require_usize(_: usize) {}
        let r = ReloadReport {
            ok: true,
            source: None,
            policy_count: 42,
            error: None,
        };
        require_usize(r.policy_count);
    }
}
