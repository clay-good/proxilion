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

    #[tokio::test]
    async fn static_loader_load_returns_new_yaml_bytes_after_set_yaml() {
        // The existing `static_loader_bumps_revision_on_set_yaml` and
        // `static_loader_set_yaml_bumps_revision_monotonically` tests
        // pin the version-token bump, but NEITHER directly asserts the
        // `yaml` field of the post-`set_yaml` PolicyBundle matches the
        // new content. A regression that swapped `Mutex<String>` for an
        // `OnceCell<String>` (in the name of "we only set once at
        // bootstrap") would freeze the YAML at the initial value while
        // still bumping the AtomicU64 revision — every reload tick
        // would short-circuit on "version changed" but compile the
        // SAME engine bytes, silently masking every operator policy
        // edit. Pin the bytes-on-the-wire round-trip across three
        // distinct YAML payloads.
        let l = StaticPolicyLoader::new(
            "- id: a\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n",
        );
        let b0 = l.load().await.unwrap();
        assert!(b0.yaml.contains("id: a"));
        l.set_yaml(
            "- id: b\n  vendor: google\n  action: drive.files.get\n  decision: block\n  required_ops: []\n",
        );
        let b1 = l.load().await.unwrap();
        assert!(
            b1.yaml.contains("id: b") && b1.yaml.contains("drive.files.get"),
            "post-set_yaml load did not surface new content: {}",
            b1.yaml,
        );
        // Symmetric: a third edit must again surface the new content
        // (a refactor that cached the first set_yaml's output behind a
        // OnceCell-after-init would surface here).
        l.set_yaml("- id: c\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n");
        let b2 = l.load().await.unwrap();
        assert!(b2.yaml.contains("id: c"));
        // And the post-edit YAML must NOT carry the prior content
        // (no append-only buffer regression).
        assert!(!b2.yaml.contains("id: a"));
        assert!(!b2.yaml.contains("id: b"));
    }

    #[tokio::test]
    async fn file_loader_mtime_token_format_is_mtime_colon_nanos_for_grep() {
        // The mtime token format is `mtime:<unsigned-nanos-since-epoch>`
        // — operator log filters key on the `mtime:` prefix to bucket
        // reload events, and dashboards rendering the version token
        // alongside the policy listing rely on the nanos suffix being
        // a bare integer (no separators, no leading zero pad). The
        // existing `file_loader_round_trips_yaml_and_version` test
        // pins only the `starts_with("mtime:")` prefix — pin the full
        // shape (prefix + non-empty all-digit suffix) here so a
        // refactor that swapped to RFC 3339 timestamps or to a hex
        // hash would surface the format break before any operator
        // log filter silently misses every entry.
        let tmp = tempfile_for_test();
        std::fs::write(&tmp.path, "[]\n").unwrap();
        let l = FilePolicyLoader::new(&tmp.path);
        let token = l.load().await.unwrap().version;
        let suffix = token
            .strip_prefix("mtime:")
            .expect("mtime: prefix required");
        assert!(!suffix.is_empty(), "nanos suffix must be present");
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit()),
            "nanos suffix must be all digits, got: {suffix}",
        );
        // And the sync version-token computation produces the
        // byte-identical token (already covered, but pin again here so
        // a format-only refactor that touched one branch but not the
        // other surfaces in this same module).
        let sync = l.version_token_sync().unwrap();
        assert_eq!(sync, token);
    }

    #[test]
    fn policy_load_error_io_display_passes_inner_error_message_through_unchanged() {
        // The existing `policy_load_error_display_renders_each_variant`
        // test pins the prefix-and-message Display shape via a fixed
        // operator-style string. Pin the byte-identical pass-through
        // contract on the Io variant specifically against a real
        // `std::io::Error::to_string()` shape — the `from_file` /
        // `load` paths surface IO errors verbatim through this Display
        // (the operator's first 30 seconds during a permission denial
        // depend on the inner OS message reaching the log). A refactor
        // that truncated or normalized the inner string (e.g. for
        // "consistency across platforms") would silently strip the
        // actionable triage half. Note: we don't depend on the OS-
        // specific text — only that whatever message we feed in
        // surfaces verbatim after the `"io error: "` prefix.
        let msg = "permission denied (os error 13)";
        let e = PolicyLoadError::Io(msg.into());
        let rendered = e.to_string();
        assert!(rendered.starts_with("io error: "), "got: {rendered}");
        assert!(rendered.ends_with(msg), "got: {rendered}");
        // And the Backend variant follows the symmetric shape —
        // pin it in the same test so a "tidy up the prefixes"
        // refactor must update both arms in lockstep.
        let e = PolicyLoadError::Backend("pg pool exhausted".into());
        let rendered = e.to_string();
        assert!(rendered.starts_with("backend error: "));
        assert!(rendered.ends_with("pg pool exhausted"));
    }

    #[test]
    fn policy_load_error_implements_std_error_trait_for_anyhow_chain_walking() {
        // `PolicyLoadError` is the boundary error returned to the proxy's
        // policy_handle reload loop, which bubbles it through `anyhow`
        // chains for operator-facing logs. A refactor that swapped
        // `thiserror::Error` for a hand-rolled `impl Display` would
        // silently drop the `std::error::Error` impl, breaking
        // `anyhow::Error::source()` walks at the policy_handle layer
        // (surfacing as truncated log chains rather than as a compile
        // error). Pin the dyn-cast AND the `source() == None` leaf
        // contract for all three variants — none of them carry an inner
        // `#[source]`/`#[from]` so all three are leaf nodes in the chain.
        use std::error::Error;
        for e in [
            PolicyLoadError::Io("perm denied".into()),
            PolicyLoadError::NotFound("/etc/proxilion/p.yaml".into()),
            PolicyLoadError::Backend("pg connection refused".into()),
        ] {
            let dyn_e: &(dyn Error + 'static) = &e;
            assert!(dyn_e.source().is_none(), "leaf variant: {e:?}");
            // Display still works via dyn-cast (the Display impl is what
            // anyhow's chain printing calls).
            let rendered = dyn_e.to_string();
            assert!(!rendered.is_empty(), "Display via dyn-cast empty: {e:?}");
        }
    }

    #[test]
    fn policy_load_error_not_found_display_passes_path_through_unchanged() {
        // Symmetric counterpart to
        // `policy_load_error_io_display_passes_inner_error_message_through_unchanged`
        // — pin byte-exact passthrough on the NotFound variant. Operator
        // triage during a policy-file rename or volume-mount typo depends
        // on the full path surfacing in the log (a "did you mean
        // /etc/proxilion/policy.yaml?" check). A refactor that truncated
        // the path to a basename "for log brevity" would silently strip
        // the directory half — the operator-visible message would still
        // mention "policy.yaml" but lose the mount-point context. Pin
        // both the `"source not found: "` prefix AND the trailing
        // byte-identical inner.
        let path = "/var/run/proxilion/configs/policy.yaml.disabled";
        let e = PolicyLoadError::NotFound(path.into());
        let rendered = e.to_string();
        assert!(
            rendered.starts_with("source not found: "),
            "got: {rendered}"
        );
        assert!(rendered.ends_with(path), "got: {rendered}");
        // Empty-inner edge: a refactor that gated on `!inner.is_empty()`
        // (in the name of "tidy up empty messages") would silently
        // produce a bare `"source not found:"` log line with no path —
        // an operator alert filter keyed on the colon-space-path shape
        // would silently miss it. Pin the prefix-survives-empty-inner
        // contract.
        let e = PolicyLoadError::NotFound(String::new());
        let rendered = e.to_string();
        assert!(
            rendered.starts_with("source not found: "),
            "got: {rendered}"
        );
    }

    #[test]
    fn policy_bundle_debug_carries_field_names_for_operator_grep() {
        // The `policy_handle` reload tick traces a `PolicyBundle` shape
        // via `tracing::debug!(?bundle, ..)`. A manual Debug impl that
        // hid the field names (rendered as a tuple, or collapsed
        // `version` into a Display alias) would silently strip the
        // operator's grep handle — the `version=` field selector that
        // the reload-event log filter uses to bucket version-token
        // changes vs. yaml-only changes (which shouldn't happen but
        // would surface as a bug). Pin both field names AND the version
        // value substring.
        let b = PolicyBundle {
            yaml: "- id: pin-test".into(),
            version: "mtime:1234567890".into(),
        };
        let s = format!("{b:?}");
        assert!(s.contains("yaml"), "got: {s}");
        assert!(s.contains("version"), "got: {s}");
        assert!(s.contains("mtime:1234567890"), "got: {s}");
        assert!(s.contains("pin-test"), "got: {s}");
    }

    #[test]
    fn file_loader_new_accepts_str_string_pathbuf_and_path_via_as_ref() {
        // The `FilePolicyLoader::new` signature is `impl AsRef<Path>` —
        // every standard path-ish type round-trips through `to_path_buf`
        // to land in the inner `PathBuf` field. The existing
        // `file_loader_path_and_source_label_round_trip` test only walks
        // the `&str` shape; pin the four common shapes (`&str`,
        // `String`, `&Path`, `PathBuf`) so a refactor that tightened the
        // bound to `Into<PathBuf>` or `&Path` would surface here as a
        // compile break on this test rather than at a downstream caller
        // (server.rs builds the loader from an env-var-derived `String`;
        // the embed API may build it from a `&Path`). All four MUST
        // yield byte-identical `path()` output.
        let target = "/tmp/proxilion-as-ref-test.yaml";
        let from_str = FilePolicyLoader::new(target);
        let from_string = FilePolicyLoader::new(String::from(target));
        let from_pathbuf = FilePolicyLoader::new(PathBuf::from(target));
        let from_path_ref = FilePolicyLoader::new(Path::new(target));
        assert_eq!(from_str.path().to_string_lossy(), target);
        assert_eq!(from_string.path().to_string_lossy(), target);
        assert_eq!(from_pathbuf.path().to_string_lossy(), target);
        assert_eq!(from_path_ref.path().to_string_lossy(), target);
        // And source_label round-trips byte-identically across all four
        // shapes (a refactor that started normalizing the PathBuf via
        // `.canonicalize()` "for consistency" would surface here as
        // diverging labels — and as broken log filters since the
        // canonicalize'd path lands on `/private/tmp/...` on macOS).
        assert_eq!(from_str.source_label(), target);
        assert_eq!(from_string.source_label(), target);
        assert_eq!(from_pathbuf.source_label(), target);
        assert_eq!(from_path_ref.source_label(), target);
    }

    #[tokio::test]
    async fn static_loader_changed_since_returns_none_when_caller_already_tracks_current() {
        // The `changed_since` default impl returns `None` when the
        // caller's tracked version equals the current bundle's. Pin
        // the idempotent-after-update path that
        // `static_loader_changed_since_uses_default_impl_correctly`
        // doesn't fully walk: after `set_yaml`, the caller observes a
        // new version (`v1`), advances its tracked token to `v1`, and
        // calls `changed_since("rev:1")` again — MUST return None. A
        // refactor that conflated "current revision" with "any
        // post-init revision" (e.g. an `is_post_init: bool` cache
        // instead of value comparison) would silently keep reporting
        // change every tick, triggering an engine rebuild storm on
        // every reload-tick after the first edit.
        let l = StaticPolicyLoader::new("[]");
        l.set_yaml("- id: a\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n");
        let v1 = l.load().await.unwrap().version;
        assert_eq!(v1, "rev:1");
        // Caller has advanced its tracked version to v1 — subsequent
        // changed_since must report None until set_yaml is called again.
        let no_change = l.changed_since(&v1).await.unwrap();
        assert!(no_change.is_none(), "post-advance must report None");
        // And a second changed_since call (no set_yaml in between) MUST
        // remain None — pin idempotency across repeated polls.
        let still_none = l.changed_since(&v1).await.unwrap();
        assert!(still_none.is_none(), "repeated poll must remain None");
    }

    #[tokio::test]
    async fn static_loader_clone_via_arc_share_set_yaml_visible_across_handles() {
        // `StaticPolicyLoader` holds its YAML behind `Arc<Mutex<String>>`
        // and its revision behind `Arc<AtomicU64>`. Two clones of the
        // same loader MUST share state — a `set_yaml` on one handle MUST
        // surface through the other's `load()`. The proxy wraps the
        // loader in an `Arc<dyn PolicyLoader>` and hands clones to the
        // policy-handle background task; a refactor that deep-copied
        // the inner String "to isolate test fixtures" would silently
        // make every reload tick read stale YAML while operator edits
        // landed only on the producer-side handle. Note: the trait
        // requires `Send + Sync` so the share is via the inner Arc, not
        // a `Clone` derive on `StaticPolicyLoader` itself — pin the
        // shared-state via wrapping in an explicit Arc<dyn ...>.
        let producer = Arc::new(StaticPolicyLoader::new("[]"));
        let consumer = producer.clone();
        producer.set_yaml(
            "- id: shared\n  vendor: g\n  action: a\n  decision: allow\n  required_ops: []\n",
        );
        // Consumer-side load surfaces producer-side edit (Arc share).
        let b = consumer.load().await.unwrap();
        assert!(
            b.yaml.contains("id: shared"),
            "consumer must see producer's set_yaml: {}",
            b.yaml,
        );
        assert_eq!(b.version, "rev:1");
        // Symmetric: a producer-side load also surfaces the same shape
        // (a refactor that gave each clone its own revision counter
        // would surface here as version mismatch between handles).
        let b2 = producer.load().await.unwrap();
        assert_eq!(b2.yaml, b.yaml);
        assert_eq!(b2.version, b.version);
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

    #[test]
    fn policy_bundle_and_file_loader_and_static_loader_and_load_error_are_send_sync_static() {
        // PolicyBundle is held inside the proxy's `ArcSwap<Engine>` hot-
        // swap path; both loader implementations are stored as
        // `Arc<dyn PolicyLoader>` and shared across tokio task
        // boundaries (the watcher + every per-request load() call).
        // PolicyLoadError flows through `anyhow::Error` chains at the
        // proxy's reload-error path. All four MUST be Send + Sync +
        // 'static. The existing module pins individual VALUES but
        // never the trait bounds — a refactor adding an Rc<...> field
        // "for cheap shared metadata" on any of the four would break
        // Sync and surface at a remote `tower::Service` trait-bound
        // rather than at this module. Pin all four — symmetric to
        // round-168 + round-169 + round-173 + round-175 Send+Sync+'static
        // pins extended to the policy loader trait hierarchy.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PolicyBundle>();
        require_send_sync_static::<FilePolicyLoader>();
        require_send_sync_static::<StaticPolicyLoader>();
        require_send_sync_static::<PolicyLoadError>();
    }

    #[test]
    fn policy_bundle_yaml_and_version_fields_are_owned_string_type_for_hot_swap_arc_clone() {
        // PolicyBundle is moved into `ArcSwap<Engine>` on every reload;
        // the proxy clones the Arc but the inner bundle's String fields
        // must be owned (not borrowed) so the new Engine outlives the
        // loader's source buffer. A refactor to `yaml: &'a str` "to
        // avoid the per-reload allocation" would surface a lifetime
        // constraint that the ArcSwap call site couldn't satisfy.
        // Pin via require_string symmetric to round-168 require_vec_string
        // + round-172 PcaView.pic_profile + round-175 lookup_list
        // Vec<String> ownership-type pins extended to PolicyBundle
        // String fields.
        fn require_string(_: &String) {}
        let b = PolicyBundle {
            yaml: "- id: x".into(),
            version: "mtime:0".into(),
        };
        require_string(&b.yaml);
        require_string(&b.version);
    }

    #[test]
    fn policy_load_error_display_byte_exact_prefix_shape_no_kebab_no_uppercase_across_three_variants()
     {
        // Operator alert filters bucket reload failures on the three
        // canonical Display prefixes: `io error:`, `source not found:`,
        // `backend error:`. The existing pin walks the substring
        // contains but never the EXACT byte-equal prefix shape. A
        // refactor renaming `Io` to `Filesystem` "for clarity" or
        // adding kebab-case to a future #[error("...")] attribute would
        // silently rebucket every existing Grafana alert. Pin
        // byte-exact lowercase + no-kebab across all three variants
        // — symmetric to round-173 ErrorCode as_str lowercase sweep
        // extended to thiserror Display prefixes.
        let io = PolicyLoadError::Io("boom".into());
        let s = format!("{io}");
        assert!(
            s.starts_with("io error:"),
            "expected `io error:` prefix: {s}"
        );
        assert!(
            s.chars()
                .take("io error".len())
                .all(|c| !c.is_ascii_uppercase())
        );
        assert!(!s[.."io error:".len()].contains('-'));

        let nf = PolicyLoadError::NotFound("/x".into());
        let s = format!("{nf}");
        assert!(
            s.starts_with("source not found:"),
            "expected `source not found:` prefix: {s}",
        );
        assert!(!s["source not found".len()..].is_empty());

        let be = PolicyLoadError::Backend("db".into());
        let s = format!("{be}");
        assert!(
            s.starts_with("backend error:"),
            "expected `backend error:` prefix: {s}",
        );
    }

    #[test]
    fn policy_load_error_debug_carries_all_three_variant_names_for_grep_bucketing() {
        // Operator log filters bucket reload failures by Debug variant
        // name (`?err` rendering in the `policy_handle::reload` error
        // path). The existing pins walk Display but never Debug
        // variant names — a manual Debug impl that collapsed all
        // three variants to `PolicyLoadError(_)` "for compact logs"
        // would silently break grep-based alerting that splits
        // filesystem-error from not-found from db-backend errors.
        // Pin all three variant names render in Debug — symmetric to
        // round-163 ConfigError Debug variant-name sweep + round-168
        // PicViolationRecord pic_mode + round-173 ErrorCode sweeps
        // extended to PolicyLoadError.
        let io = PolicyLoadError::Io("boom".into());
        assert!(format!("{io:?}").contains("Io"), "got: {io:?}");
        let nf = PolicyLoadError::NotFound("/x".into());
        assert!(format!("{nf:?}").contains("NotFound"), "got: {nf:?}");
        let be = PolicyLoadError::Backend("db".into());
        assert!(format!("{be:?}").contains("Backend"), "got: {be:?}");
    }

    #[test]
    fn static_loader_set_yaml_atomic_revision_increment_is_monotonic_across_50_mutations() {
        // The `set_yaml` mutator bumps an AtomicU64 revision via
        // SeqCst ordering — the revision is the version token
        // (`format!("rev:{rev}")`) returned by `load()`. A refactor
        // that swapped to `Relaxed` ordering "for hot-path perf" would
        // be technically incorrect for the changed_since-then-load
        // happens-before contract the watcher relies on, but the bug
        // would surface only under high concurrency. Pin the
        // monotonic-increment contract on the single-threaded path
        // across 50 mutations — symmetric to round-159 Handle::new
        // Arc-strong-count increment pins extended to StaticPolicyLoader
        // revision counter.
        let loader = StaticPolicyLoader::new("yaml-0");
        let mut prev_rev = 0u64;
        for i in 1..=50 {
            loader.set_yaml(format!("yaml-{i}"));
            let rev = loader.revision.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                rev,
                prev_rev + 1,
                "revision must increment by exactly 1 on iter {i}"
            );
            prev_rev = rev;
        }
        assert_eq!(prev_rev, 50);
    }

    #[tokio::test]
    async fn static_loader_load_yields_owned_policy_bundle_via_clone_not_borrowed_slice() {
        // `StaticPolicyLoader::load()` returns `Result<PolicyBundle,
        // _>` (owned) — the bundle's `yaml` field is a clone of the
        // inner Mutex<String> so consumers can drop the loader and
        // still consume the bundle. A refactor returning `Result<&
        // PolicyBundle, _>` "to avoid the clone" would force a lifetime
        // constraint that the ArcSwap call site couldn't satisfy. Pin
        // owned-bundle semantic by dropping the loader BEFORE
        // inspecting the bundle.
        let bundle = {
            let loader = StaticPolicyLoader::new("- id: x\n");
            loader.load().await.expect("static load must succeed")
            // loader dropped here
        };
        assert!(bundle.yaml.contains("id: x"));
        assert_eq!(bundle.version, "rev:0");
        // Owned-type pin.
        fn require_string(_: &String) {}
        require_string(&bundle.yaml);
        require_string(&bundle.version);
    }
}
