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
    /// + the loader's new version token. Used by the watcher when a
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
    /// `POST /api/v1/policy/{id}/mode`. Returns true iff a policy with
    /// that id existed and was updated. The YAML round-trip is best-
    /// effort using `serde_yaml` — comments are NOT preserved (ui-less-
    /// surfaces.md §11.1 open question); a future CST-preserving editor
    /// would replace this.
    pub fn set_mode(&self, policy_id: &str, mode: Mode) -> Result<ReloadReport, SetModeError> {
        let yaml = self.raw_yaml.load_full();
        let mut docs: Vec<serde_yaml::Value> =
            serde_yaml::from_str(&yaml).map_err(|e| SetModeError::Parse(e.to_string()))?;
        let mut found = false;
        for d in docs.iter_mut() {
            let Some(map) = d.as_mapping_mut() else { continue };
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
        let new_yaml = serde_yaml::to_string(&docs).map_err(|e| SetModeError::Parse(e.to_string()))?;
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
    let mut last_mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(t) => Some(t),
        Err(_) => None,
    };
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
}
