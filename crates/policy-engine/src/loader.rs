//! Pluggable policy backend — qiuth-patterns.md §5.
//!
//! The engine knows how to compile and evaluate; it does **not** know
//! where the YAML came from. A [`PolicyLoader`] hides that:
//!
//! - [`FilePolicyLoader`] reads from disk; used by the proxy in production.
//! - [`StaticPolicyLoader`] holds the YAML inline; used by tests.
//! - A future `DbPolicyLoader` (per-customer YAML rows) drops in without
//!   touching anything in `crates/proxy`.
//!
//! The trait is intentionally minimal — `load()` returns the current YAML
//! snapshot plus a `version` token the caller can use to short-circuit
//! identical reloads. Compilation happens in the caller, not the loader,
//! so a transient parse failure in a freshly-edited YAML doesn't take a
//! known-good backend offline.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// One snapshot of the policy source. `version` is opaque — it could be
/// an mtime, a content hash, a Postgres `xmin`, or a row revision id. The
/// caller only compares it for equality (skip-reload if unchanged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundle {
    pub yaml: String,
    pub version: String,
}

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("io error: {0}")]
    Io(String),
    #[error("source not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Pluggable backend for the policy YAML. Implementations are expected to
/// be cheap to `clone` (use `Arc` internally) — the proxy holds one
/// `Arc<dyn PolicyLoader>` for the lifetime of the process.
#[async_trait]
pub trait PolicyLoader: Send + Sync {
    /// Returns the current YAML snapshot. Idempotent — callers may invoke
    /// it on every reload tick. Implementations cache as appropriate.
    async fn load(&self) -> Result<PolicyBundle, PolicyLoadError>;

    /// Stable label for logs and error messages.
    fn source_label(&self) -> String;

    /// Optional: returns `Some(new_version)` if the backend's content has
    /// changed since `current_version`, else `None`. The default polls
    /// `load()` and compares — implementations with a cheap watcher
    /// (mtime, pg LISTEN) should override.
    async fn changed_since(
        &self,
        current_version: &str,
    ) -> Result<Option<String>, PolicyLoadError> {
        let b = self.load().await?;
        Ok(if b.version != current_version {
            Some(b.version)
        } else {
            None
        })
    }
}

// -- File loader --------------------------------------------------------

/// Reads from a single YAML file. Version token is the file's mtime
/// rendered as a stable string. Matches the existing
/// `crates/proxy/src/policy_handle.rs` watcher semantics.
pub struct FilePolicyLoader {
    path: PathBuf,
}

impl FilePolicyLoader {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Synchronous version-token computation. Useful at bootstrap when
    /// the caller isn't yet inside a runtime ready to await the async
    /// `load()`.
    pub fn version_token_sync(&self) -> Result<String, PolicyLoadError> {
        self.mtime_token()
    }

    fn mtime_token(&self) -> Result<String, PolicyLoadError> {
        let meta = std::fs::metadata(&self.path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                PolicyLoadError::NotFound(self.path.display().to_string())
            }
            _ => PolicyLoadError::Io(e.to_string()),
        })?;
        let modified = meta
            .modified()
            .map_err(|e| PolicyLoadError::Io(e.to_string()))?;
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Ok(format!("mtime:{secs}"))
    }
}

#[async_trait]
impl PolicyLoader for FilePolicyLoader {
    async fn load(&self) -> Result<PolicyBundle, PolicyLoadError> {
        let yaml = std::fs::read_to_string(&self.path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                PolicyLoadError::NotFound(self.path.display().to_string())
            }
            _ => PolicyLoadError::Io(e.to_string()),
        })?;
        let version = self.mtime_token()?;
        Ok(PolicyBundle { yaml, version })
    }

    fn source_label(&self) -> String {
        self.path.display().to_string()
    }

    async fn changed_since(
        &self,
        current_version: &str,
    ) -> Result<Option<String>, PolicyLoadError> {
        let v = self.mtime_token()?;
        Ok(if v != current_version { Some(v) } else { None })
    }
}

// -- Static loader (tests, embed paths) --------------------------------

/// In-memory loader. Useful for unit tests and embedded scenarios where
/// the caller already has the YAML in hand.
pub struct StaticPolicyLoader {
    yaml: Arc<Mutex<String>>,
    label: String,
    revision: Arc<std::sync::atomic::AtomicU64>,
}

impl StaticPolicyLoader {
    pub fn new(yaml: impl Into<String>) -> Self {
        Self {
            yaml: Arc::new(Mutex::new(yaml.into())),
            label: "static".into(),
            revision: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Mutate the in-memory YAML. Bumps the revision so subsequent
    /// `changed_since(...)` calls return `Some(new)`.
    pub fn set_yaml(&self, yaml: impl Into<String>) {
        *self.yaml.lock().expect("static loader mutex") = yaml.into();
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl PolicyLoader for StaticPolicyLoader {
    async fn load(&self) -> Result<PolicyBundle, PolicyLoadError> {
        let yaml = self.yaml.lock().expect("static loader mutex").clone();
        let rev = self.revision.load(std::sync::atomic::Ordering::SeqCst);
        Ok(PolicyBundle {
            yaml,
            version: format!("rev:{rev}"),
        })
    }

    fn source_label(&self) -> String {
        self.label.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn file_loader_round_trips_yaml_and_version() {
        let mut tmp = tempfile_for_test();
        writeln!(tmp.file, "- id: t1\n  vendor: google\n  action: drive.files.get\n  decision: allow\n  required_ops: []").unwrap();
        tmp.file.flush().unwrap();
        let l = FilePolicyLoader::new(&tmp.path);
        let b = l.load().await.expect("loads");
        assert!(b.yaml.contains("id: t1"));
        assert!(b.version.starts_with("mtime:"));
        // No change yet.
        assert!(l.changed_since(&b.version).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_loader_detects_change_via_mtime() {
        let mut tmp = tempfile_for_test();
        writeln!(tmp.file, "[]").unwrap();
        tmp.file.flush().unwrap();
        let l = FilePolicyLoader::new(&tmp.path);
        let b0 = l.load().await.unwrap();

        // Bump mtime by writing again (sleep to ensure resolution).
        std::thread::sleep(std::time::Duration::from_millis(15));
        // Recreate the file's mtime by truncating + rewriting.
        std::fs::write(
            &tmp.path,
            "- id: x\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n",
        )
        .unwrap();

        let changed = l.changed_since(&b0.version).await.unwrap();
        assert!(changed.is_some(), "expected a new mtime token");
    }

    #[tokio::test]
    async fn file_loader_reports_not_found() {
        let l = FilePolicyLoader::new("/definitely/does/not/exist/proxilion-test.yaml");
        let e = l.load().await.unwrap_err();
        assert!(matches!(e, PolicyLoadError::NotFound(_)));
    }

    #[tokio::test]
    async fn static_loader_bumps_revision_on_set_yaml() {
        let l = StaticPolicyLoader::new("[]").with_label("test");
        let v0 = l.load().await.unwrap().version;
        l.set_yaml("- id: x\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n");
        let v1 = l.load().await.unwrap().version;
        assert_ne!(v0, v1);
        let c = l.changed_since(&v0).await.unwrap();
        assert_eq!(c.as_deref(), Some(v1.as_str()));
    }

    #[test]
    fn policy_load_error_display_renders_each_variant() {
        // Operator-facing strings — log filters and Grafana alerts key on
        // the `io error:` / `source not found:` / `backend error:` prefixes,
        // so a future variant rename must be a conscious wire-shape change.
        assert_eq!(
            PolicyLoadError::Io("perm denied".into()).to_string(),
            "io error: perm denied",
        );
        assert_eq!(
            PolicyLoadError::NotFound("/etc/proxilion/policy.yaml".into()).to_string(),
            "source not found: /etc/proxilion/policy.yaml",
        );
        assert_eq!(
            PolicyLoadError::Backend("pg connection refused".into()).to_string(),
            "backend error: pg connection refused",
        );
    }

    #[test]
    fn policy_bundle_equality_ignores_neither_yaml_nor_version() {
        let a = PolicyBundle {
            yaml: "[]".into(),
            version: "v1".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = PolicyBundle {
            yaml: "[]".into(),
            version: "v2".into(),
        };
        assert_ne!(a, c, "version diff alone breaks equality");
        let d = PolicyBundle {
            yaml: "- id: x".into(),
            version: "v1".into(),
        };
        assert_ne!(a, d, "yaml diff alone breaks equality");
    }

    #[test]
    fn file_loader_path_and_source_label_round_trip() {
        let l = FilePolicyLoader::new("/tmp/proxilion-doesnt-matter.yaml");
        assert_eq!(
            l.path().to_string_lossy(),
            "/tmp/proxilion-doesnt-matter.yaml"
        );
        assert_eq!(l.source_label(), "/tmp/proxilion-doesnt-matter.yaml");
    }

    #[tokio::test]
    async fn file_loader_version_token_sync_matches_async_load() {
        let tmp = tempfile_for_test();
        std::fs::write(&tmp.path, "[]\n").unwrap();
        let l = FilePolicyLoader::new(&tmp.path);
        let sync_token = l.version_token_sync().expect("sync token");
        assert!(sync_token.starts_with("mtime:"));
        let async_token = l.load().await.unwrap().version;
        assert_eq!(sync_token, async_token);
    }

    #[test]
    fn file_loader_version_token_sync_reports_not_found() {
        let l = FilePolicyLoader::new("/definitely/not/here/proxilion.yaml");
        let e = l.version_token_sync().unwrap_err();
        assert!(
            matches!(e, PolicyLoadError::NotFound(_)),
            "expected NotFound, got {e:?}",
        );
    }

    #[tokio::test]
    async fn static_loader_initial_version_is_rev_zero() {
        // Pin the initial revision token shape — `"rev:0"`. The
        // proxy bootstraps the policy handle with this token, and a
        // refactor that started at `"rev:1"` (or a UUID) would make
        // every first reload tick fire an unnecessary engine rebuild
        // because the handle's pinned-zero would mismatch.
        let l = StaticPolicyLoader::new("[]");
        let v = l.load().await.unwrap().version;
        assert_eq!(v, "rev:0");
    }

    #[tokio::test]
    async fn static_loader_changed_since_uses_default_impl_correctly() {
        // The `StaticPolicyLoader` does NOT override `changed_since`,
        // so it inherits the trait default (which polls `load()` and
        // compares versions). Pin the default-impl path end-to-end:
        // initial → no change, after set_yaml → change reported.
        let l = StaticPolicyLoader::new("[]");
        let v0 = l.load().await.unwrap().version;
        let same = l.changed_since(&v0).await.unwrap();
        assert!(same.is_none(), "no edits → no change");
        l.set_yaml("- id: a\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n");
        let changed = l.changed_since(&v0).await.unwrap();
        assert!(changed.is_some(), "set_yaml must surface as a change");
        assert_eq!(changed.as_deref(), Some("rev:1"));
    }

    #[tokio::test]
    async fn static_loader_set_yaml_bumps_revision_monotonically() {
        // Each set_yaml call MUST bump the revision counter exactly
        // once (atomic fetch_add). Pin five successive bumps so a
        // refactor to `swap` (which would reset on every call) or to
        // a non-atomic store (where two concurrent set_yamls could
        // land the same revision) would surface here.
        let l = StaticPolicyLoader::new("[]");
        for expected in 1..=5 {
            l.set_yaml(format!("rev: {expected}"));
            let v = l.load().await.unwrap().version;
            assert_eq!(v, format!("rev:{expected}"));
        }
    }

    #[test]
    fn static_loader_with_label_overrides_default_source_label() {
        let l = StaticPolicyLoader::new("[]");
        assert_eq!(l.source_label(), "static");
        let l = StaticPolicyLoader::new("[]").with_label("inline-test");
        assert_eq!(l.source_label(), "inline-test");
    }

    struct Tmp {
        path: PathBuf,
        file: std::fs::File,
    }

    fn tempfile_for_test() -> Tmp {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "proxilion-loader-test-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create(&path).unwrap();
        Tmp { path, file }
    }
}
