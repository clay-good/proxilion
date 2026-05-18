//! Chain verifier — walks `pca_cache` from a leaf back to PCA_0 and checks
//! every PIC invariant.
//!
//! Authority: spec.md §1.5.
//!
//! Invariants enforced per hop:
//!   1. CAT signature: each `SignedPca` verifies against a Trust Plane key
//!      we trust (currently a single key fetched via §1.2 `CatKeyRegistry`).
//!   2. Continuity: the predecessor's CAT signature equals
//!      `current.provenance.cat_sig` (the cryptographic link). PCA_0 has
//!      no `provenance` — that's how we know we reached the origin.
//!   3. Identity (monotonicity): every op in `current.ops` is also in
//!      `predecessor.ops`.
//!   4. Provenance (p_0 immutability): `current.p_0 == predecessor.p_0`.
//!   5. Hop ordering: `current.hop == predecessor.hop + 1`, and the leaf's
//!      `predecessor_id` chain terminates at a node whose `hop == 0`.
//!
//! Results are cached for 60s by leaf id (moka). Persistent caching to
//! `pca_verification_results` is the dashboard's job (§1.6).

use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use serde::Serialize;
use shared_types::provenance::crypto::SignedPca;
use shared_types::provenance::pca::Pca;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::{CachedPca, CatKeyRegistry, PcaCache};

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("pca {0} not found in cache")]
    Missing(Uuid),
    #[error("CAT signature failed to verify on pca {0}")]
    BadCatSignature(Uuid),
    #[error(
        "continuity broken between pca {child} and predecessor {parent}: provenance.cat_sig mismatch"
    )]
    ContinuityBroken { child: Uuid, parent: Uuid },
    #[error("monotonicity violated: {missing} not in predecessor's ops")]
    Monotonicity { missing: String },
    #[error("p_0 changed across hop ({child_p0} != {parent_p0})")]
    P0Mismatch { child_p0: String, parent_p0: String },
    #[error("hop ordering: child hop {child} != parent hop {parent} + 1")]
    HopOrder { child: u32, parent: u32 },
    #[error("decoding signed PCA bytes: {0}")]
    Decode(String),
    #[error("CAT key fetch: {0}")]
    CatKey(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    pub intact: bool,
    pub links_verified: usize,
    pub p_0: Option<String>,
    pub broken_at: Option<Uuid>,
    pub reason: Option<String>,
    /// PIC profile pinned on every link in the chain (spec.md §15 #11).
    /// `None` only when the chain is broken before any link was loaded.
    /// `mismatch_at` is set when a chain mixes profiles — strict
    /// enforcement of "all links share one profile" is a v2 hardening;
    /// today the verifier surfaces the field so dashboards / audits can
    /// detect drift without us bumping the rejection-rate on day one.
    pub pic_profile: Option<String>,
    pub pic_profile_mismatch_at: Option<Uuid>,
}

#[derive(Clone)]
pub struct PicVerifier {
    pca_cache: PcaCache,
    cat_keys: CatKeyRegistry,
    cache: Cache<Uuid, Arc<VerificationResult>>,
}

impl PicVerifier {
    pub fn new(pca_cache: PcaCache, cat_keys: CatKeyRegistry) -> Self {
        Self {
            pca_cache,
            cat_keys,
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(60))
                .build(),
        }
    }

    /// Walk from `leaf_pca_id` to PCA_0; 60s-cached by leaf id.
    #[instrument(skip(self))]
    pub async fn verify_chain(
        &self,
        leaf_pca_id: Uuid,
    ) -> Result<Arc<VerificationResult>, VerifierError> {
        if let Some(hit) = self.cache.get(&leaf_pca_id).await {
            // Cache hits don't tick the verify counter — they're free
            // re-fetches of a prior verification, not new verifications.
            return Ok(hit);
        }
        // spec.md §3.2 — `proxilion_pca_verify_total{result="intact|broken"}`
        // + `proxilion_pca_verify_duration_seconds` histogram. Measured on
        // the cold path only (cache misses); §1.5's p99 budget is "<5ms
        // warm / <20ms cold," and warm is by-construction free here.
        let started = Instant::now();
        let result = self.walk(leaf_pca_id).await;
        let (arc, violation_kind) = match result {
            Ok(r) => (Arc::new(r), None),
            Err(ref e) => (
                Arc::new(err_to_result(leaf_pca_id, e)),
                Some(invariant_kind(e)),
            ),
        };
        let result_label = if arc.intact { "intact" } else { "broken" };
        metrics::counter!(
            "proxilion_pca_verify_total",
            "result" => result_label,
        )
        .increment(1);
        if let Some(kind) = violation_kind {
            // spec.md §3.2 — `proxilion_pic_invariant_violations_total{kind}`.
            // Mirrors the verifier-detected break to the Prometheus contract.
            // Layer-A runtime-gate refusals (Trust-Plane-side) already tick
            // `proxilion_pic_violations_total` with `mode=runtime_gate` from
            // pic/executor.rs; this counter is the chain-verifier's view of
            // *historical* chain tampering, which is a distinct signal.
            metrics::counter!(
                "proxilion_pic_invariant_violations_total",
                "kind" => kind,
            )
            .increment(1);
        }
        metrics::histogram!("proxilion_pca_verify_duration_seconds")
            .record(started.elapsed().as_secs_f64());
        self.cache.insert(leaf_pca_id, arc.clone()).await;
        Ok(arc)
    }

    async fn walk(&self, leaf_pca_id: Uuid) -> Result<VerificationResult, VerifierError> {
        let key = self
            .cat_keys
            .get()
            .await
            .map_err(|e| VerifierError::CatKey(e.to_string()))?;

        let mut current_id = leaf_pca_id;
        let mut links_verified = 0usize;
        let mut p_0: Option<String> = None;
        let mut chain_profile: Option<String> = None;
        let mut profile_mismatch_at: Option<Uuid> = None;

        loop {
            let cached = self
                .pca_cache
                .get(current_id)
                .await
                .map_err(|e| VerifierError::CatKey(e.to_string()))?
                .ok_or(VerifierError::Missing(current_id))?;
            let (signed_current, pca_current) = decode(&cached, current_id)?;

            key.verify_pca(&signed_current)
                .map_err(|_| VerifierError::BadCatSignature(current_id))?;
            links_verified += 1;
            p_0.get_or_insert_with(|| pca_current.p_0.value.clone());
            // Track the chain's PIC profile. First link sets it; subsequent
            // links that disagree get recorded as a mismatch (not yet a
            // hard error — surfaces the drift in API output for audit).
            match chain_profile.as_deref() {
                None => chain_profile = Some(cached.pic_profile.clone()),
                Some(prev) if prev == cached.pic_profile => {}
                Some(_) => {
                    profile_mismatch_at.get_or_insert(current_id);
                }
            }

            match cached.predecessor_id {
                None => {
                    // PCA_0: hop must be 0; no provenance must be present.
                    if pca_current.hop != 0 || pca_current.provenance.is_some() {
                        return Err(VerifierError::HopOrder {
                            child: pca_current.hop,
                            parent: 0,
                        });
                    }
                    break;
                }
                Some(parent_id) => {
                    let parent_cached = self
                        .pca_cache
                        .get(parent_id)
                        .await
                        .map_err(|e| VerifierError::CatKey(e.to_string()))?
                        .ok_or(VerifierError::Missing(parent_id))?;
                    let (signed_parent, pca_parent) = decode(&parent_cached, parent_id)?;
                    check_invariants(
                        &pca_current,
                        &pca_parent,
                        current_id,
                        parent_id,
                        &signed_parent,
                    )?;
                    current_id = parent_id;
                }
            }
        }

        Ok(VerificationResult {
            intact: true,
            links_verified,
            p_0,
            broken_at: None,
            reason: None,
            pic_profile: chain_profile,
            pic_profile_mismatch_at: profile_mismatch_at,
        })
    }
}

/// Pure invariant check between a child PCA and its predecessor. Splits the
/// crypto continuity link (`child.provenance.cat_sig == parent_signed.signature()`)
/// from the structural invariants (hop / p_0 / monotonicity) so callers
/// (incl. tests) can drive each piece in isolation.
fn check_invariants(
    child: &Pca,
    parent: &Pca,
    child_id: Uuid,
    parent_id: Uuid,
    parent_signed: &SignedPca,
) -> Result<(), VerifierError> {
    let prov = child
        .provenance
        .as_ref()
        .ok_or(VerifierError::ContinuityBroken {
            child: child_id,
            parent: parent_id,
        })?;
    if prov.cat_sig != parent_signed.signature() {
        return Err(VerifierError::ContinuityBroken {
            child: child_id,
            parent: parent_id,
        });
    }
    if child.hop != parent.hop + 1 {
        return Err(VerifierError::HopOrder {
            child: child.hop,
            parent: parent.hop,
        });
    }
    if child.p_0 != parent.p_0 {
        return Err(VerifierError::P0Mismatch {
            child_p0: child.p_0.value.clone(),
            parent_p0: parent.p_0.value.clone(),
        });
    }
    for op in &child.ops {
        if !parent.ops.iter().any(|o| o == op) {
            return Err(VerifierError::Monotonicity {
                missing: op.clone(),
            });
        }
    }
    Ok(())
}

fn decode(cached: &CachedPca, id: Uuid) -> Result<(SignedPca, Pca), VerifierError> {
    let signed = SignedPca::from_bytes(&cached.cbor)
        .map_err(|e| VerifierError::Decode(format!("pca {id}: {e}")))?;
    let pca = signed
        .extract_pca()
        .map_err(|e| VerifierError::Decode(format!("pca {id}: {e}")))?;
    Ok((signed, pca))
}

/// Map a `VerifierError` to the spec.md §3.2 `kind` label set
/// (`continuity | monotonicity | p0 | hop | signature`) — plus three
/// out-of-contract buckets (`missing | decode | cat_key`) for the
/// "could not even walk the chain" failures that the spec's enum doesn't
/// directly name. Bounded label cardinality.
fn invariant_kind(e: &VerifierError) -> &'static str {
    match e {
        VerifierError::ContinuityBroken { .. } => "continuity",
        VerifierError::Monotonicity { .. } => "monotonicity",
        VerifierError::P0Mismatch { .. } => "p0",
        VerifierError::HopOrder { .. } => "hop",
        VerifierError::BadCatSignature(_) => "signature",
        VerifierError::Missing(_) => "missing",
        VerifierError::Decode(_) => "decode",
        VerifierError::CatKey(_) => "cat_key",
    }
}

fn err_to_result(leaf_id: Uuid, e: &VerifierError) -> VerificationResult {
    let broken_at = match e {
        VerifierError::Missing(id) => Some(*id),
        VerifierError::BadCatSignature(id) => Some(*id),
        VerifierError::ContinuityBroken { child, .. } => Some(*child),
        _ => Some(leaf_id),
    };
    VerificationResult {
        intact: false,
        links_verified: 0,
        p_0: None,
        broken_at,
        reason: Some(e.to_string()),
        pic_profile: None,
        pic_profile_mismatch_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::provenance::{
        crypto::KeyPair,
        pca::{ExecutorBinding, PcaBuilder, Provenance},
        types::PrincipalIdentifier,
    };

    fn signed_pca_0(cat: &KeyPair, p_0: &str, ops: &[&str]) -> (Uuid, Vec<u8>, Pca) {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc(p_0))
            .ops(ops.iter().map(|s| (*s).to_string()).collect())
            .executor(ExecutorBinding::new().with("service", "test"))
            .build_pca_0()
            .unwrap();
        let signed = cat.sign_pca(&pca).unwrap();
        (Uuid::new_v4(), signed.to_bytes().unwrap(), pca)
    }

    fn signed_pca_successor(
        cat: &KeyPair,
        executor: &KeyPair,
        predecessor: &Pca,
        predecessor_signed: &SignedPca,
        ops: &[&str],
    ) -> (Uuid, Vec<u8>, Pca) {
        let prov = Provenance {
            cat_kid: cat.kid().to_string(),
            cat_sig: predecessor_signed.signature().to_vec(),
            executor_kid: executor.kid().to_string(),
            executor_sig: vec![0xab; 64], // not verified in our chain walker
        };
        let pca = PcaBuilder::new()
            .ops(ops.iter().map(|s| (*s).to_string()).collect())
            .executor(ExecutorBinding::new().with("service", "test"))
            .build_successor(predecessor, prov)
            .unwrap();
        let signed = cat.sign_pca(&pca).unwrap();
        (Uuid::new_v4(), signed.to_bytes().unwrap(), pca)
    }

    fn into_cached(id: Uuid, cbor: Vec<u8>, pca: &Pca, predecessor: Option<Uuid>) -> CachedPca {
        CachedPca {
            pca_id: id,
            cbor,
            p_0: pca.p_0.value.clone(),
            ops: pca.ops.clone(),
            hop: pca.hop as i32,
            predecessor_id: predecessor,
            signature: vec![],
            pic_profile: crate::pic::cache::CURRENT_PIC_PROFILE.to_string(),
        }
    }

    // Pure unit tests on the chain logic — no DB or HTTP required. We
    // exercise the same `decode` + invariant checks via a hand-built chain.
    fn build_three_deep() -> (KeyPair, Vec<CachedPca>) {
        let cat = KeyPair::generate("cat-test");
        let executor = KeyPair::generate("proxy-test");

        let (id0, cbor0, pca0) = signed_pca_0(
            &cat,
            "alice@demo.local",
            &["drive:read:engineering/*", "gmail:send:alice"],
        );
        let signed0 = SignedPca::from_bytes(&cbor0).unwrap();

        let (id1, cbor1, pca1) = signed_pca_successor(
            &cat,
            &executor,
            &pca0,
            &signed0,
            &["drive:read:engineering/*"],
        );
        let signed1 = SignedPca::from_bytes(&cbor1).unwrap();

        let (id2, cbor2, pca2) = signed_pca_successor(
            &cat,
            &executor,
            &pca1,
            &signed1,
            &["drive:read:engineering/*"],
        );

        (
            cat,
            vec![
                into_cached(id0, cbor0, &pca0, None),
                into_cached(id1, cbor1, &pca1, Some(id0)),
                into_cached(id2, cbor2, &pca2, Some(id1)),
            ],
        )
    }

    // Verifier internals are private; we test by reaching into `decode` +
    // invariant logic via a small in-memory PcaCache replacement. The
    // happy-path proves the chain shape decodes; tamper tests prove the
    // invariants catch corruption.

    #[test]
    fn three_deep_chain_decodes_with_consistent_invariants() {
        let (cat, chain) = build_three_deep();
        let pk = cat.public_key();

        // Walk manually using `decode` + the same checks `walk` does.
        let mut id = chain[2].pca_id;
        let mut hops = 0;
        loop {
            let row = chain.iter().find(|c| c.pca_id == id).unwrap();
            let (signed, pca) = decode(row, id).unwrap();
            pk.verify_pca(&signed).expect("CAT sig must verify");
            hops += 1;
            match row.predecessor_id {
                None => {
                    assert_eq!(pca.hop, 0);
                    break;
                }
                Some(parent) => {
                    let parent_row = chain.iter().find(|c| c.pca_id == parent).unwrap();
                    let (parent_signed, parent_pca) = decode(parent_row, parent).unwrap();
                    let prov = pca.provenance.as_ref().unwrap();
                    assert_eq!(prov.cat_sig, parent_signed.signature());
                    assert_eq!(pca.hop, parent_pca.hop + 1);
                    assert_eq!(pca.p_0, parent_pca.p_0);
                    for op in &pca.ops {
                        assert!(parent_pca.ops.contains(op));
                    }
                    id = parent;
                }
            }
        }
        assert_eq!(hops, 3);
    }

    #[test]
    fn tampered_payload_caught_by_cat_signature() {
        let (cat, mut chain) = build_three_deep();
        let pk = cat.public_key();
        // Tamper the middle PCA's payload. The midpoint byte happens to
        // land in different CBOR regions across chain rebuilds (uuid
        // randomness shifts the layout): sometimes it's in the payload
        // (signature verify catches it), sometimes it's a length / map
        // header byte (decode catches it earlier). EITHER outcome is a
        // successful "tampering rejected" — what we're asserting is that
        // an XOR'd byte never sails through to a valid SignedPca whose
        // signature still verifies. Loop the tamper byte across the
        // middle quartile so we exercise both paths in a single run.
        let idx = 1;
        let len = chain[idx].cbor.len();
        let start = len / 4;
        let stop = (3 * len) / 4;
        for pos in start..stop {
            let mut tampered = chain[idx].cbor.clone();
            tampered[pos] ^= 0x01;
            let cached = super::CachedPca {
                cbor: tampered,
                ..chain[idx].clone()
            };
            match decode(&cached, cached.pca_id) {
                Err(_) => { /* CBOR rejected — tampering caught */ }
                Ok((signed, _)) => assert!(
                    pk.verify_pca(&signed).is_err(),
                    "tampered byte at pos {pos} passed both decode AND signature verify",
                ),
            }
        }
        // Also exercise the original "midpoint byte" scenario explicitly
        // so this stays a regression test for the spec-cited "tampered
        // payload caught" path (spec.md §1.5).
        let mid = len / 2;
        chain[idx].cbor[mid] ^= 0x01;
        match decode(&chain[idx], chain[idx].pca_id) {
            Err(_) => { /* ok — tampering caught at decode */ }
            Ok((signed, _)) => assert!(pk.verify_pca(&signed).is_err()),
        }
    }

    #[test]
    fn check_invariants_catches_monotonicity_violation() {
        let (cat, chain) = build_three_deep();

        // Decode parent (PCA_0) and clone child (PCA_1) into a tampered
        // version whose ops include something the parent never granted.
        let (_signed0, pca0) = decode(&chain[0], chain[0].pca_id).unwrap();
        let (signed1, mut pca1) = decode(&chain[1], chain[1].pca_id).unwrap();
        pca1.ops.push("calendar:write:everything".to_string());

        let err = check_invariants(
            &pca1,
            &pca0,
            chain[1].pca_id,
            chain[0].pca_id,
            &SignedPca::from_bytes(&chain[0].cbor).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifierError::Monotonicity { ref missing } if missing == "calendar:write:everything"),
            "got {err:?}"
        );
        let _ = signed1;
        let _ = cat;
    }

    #[test]
    fn check_invariants_catches_continuity_break() {
        let (_cat, chain) = build_three_deep();
        let (_signed0, pca0) = decode(&chain[0], chain[0].pca_id).unwrap();
        let (_signed1, mut pca1) = decode(&chain[1], chain[1].pca_id).unwrap();

        // Tamper the continuity link.
        if let Some(prov) = pca1.provenance.as_mut() {
            prov.cat_sig[0] ^= 0x01;
        }

        let err = check_invariants(
            &pca1,
            &pca0,
            chain[1].pca_id,
            chain[0].pca_id,
            &SignedPca::from_bytes(&chain[0].cbor).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifierError::ContinuityBroken { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn check_invariants_catches_p0_drift() {
        use shared_types::provenance::types::{PrincipalIdentifier, PrincipalType};
        let (_cat, chain) = build_three_deep();
        let (_signed0, pca0) = decode(&chain[0], chain[0].pca_id).unwrap();
        let (_signed1, mut pca1) = decode(&chain[1], chain[1].pca_id).unwrap();
        pca1.p_0 = PrincipalIdentifier::new(PrincipalType::Oidc, "user:eve@evil.local");

        let err = check_invariants(
            &pca1,
            &pca0,
            chain[1].pca_id,
            chain[0].pca_id,
            &SignedPca::from_bytes(&chain[0].cbor).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifierError::P0Mismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn invariant_kind_labels_are_bounded_and_stable() {
        // Bounded label cardinality is the load-bearing property — the
        // `proxilion_pca_verify_failures_total{kind=...}` metric uses
        // these as labels, and a Prometheus cardinality explosion would
        // surface as an OOM. Pin every kind to its stable string.
        let dummy_id = Uuid::nil();
        assert_eq!(
            invariant_kind(&VerifierError::ContinuityBroken {
                child: dummy_id,
                parent: dummy_id,
            }),
            "continuity",
        );
        assert_eq!(
            invariant_kind(&VerifierError::Monotonicity {
                missing: "x".into(),
            }),
            "monotonicity",
        );
        assert_eq!(
            invariant_kind(&VerifierError::P0Mismatch {
                child_p0: "a".into(),
                parent_p0: "b".into(),
            }),
            "p0",
        );
        assert_eq!(
            invariant_kind(&VerifierError::HopOrder {
                child: 2,
                parent: 0,
            }),
            "hop",
        );
        assert_eq!(
            invariant_kind(&VerifierError::BadCatSignature(dummy_id)),
            "signature",
        );
        assert_eq!(invariant_kind(&VerifierError::Missing(dummy_id)), "missing");
        assert_eq!(invariant_kind(&VerifierError::Decode("x".into())), "decode",);
        assert_eq!(
            invariant_kind(&VerifierError::CatKey("x".into())),
            "cat_key",
        );
    }

    #[test]
    fn err_to_result_pins_broken_at_to_named_pca_when_known() {
        // The dashboard's chain-walker UI keys on `broken_at` to highlight
        // the failed link. Three variants carry an explicit id —
        // `Missing`, `BadCatSignature`, `ContinuityBroken` — and must
        // surface that, not the leaf id. The rest fall back to the leaf.
        let leaf = Uuid::new_v4();
        let other = Uuid::new_v4();
        let r = err_to_result(leaf, &VerifierError::Missing(other));
        assert_eq!(r.broken_at, Some(other));
        let r = err_to_result(leaf, &VerifierError::BadCatSignature(other));
        assert_eq!(r.broken_at, Some(other));
        let r = err_to_result(
            leaf,
            &VerifierError::ContinuityBroken {
                child: other,
                parent: leaf,
            },
        );
        assert_eq!(
            r.broken_at,
            Some(other),
            "ContinuityBroken surfaces the child id, not parent or leaf",
        );
        // Fallback path: Monotonicity has no id, so we report the leaf.
        let r = err_to_result(
            leaf,
            &VerifierError::Monotonicity {
                missing: "x".into(),
            },
        );
        assert_eq!(r.broken_at, Some(leaf));
    }

    #[test]
    fn err_to_result_marks_chain_not_intact_and_carries_reason_string() {
        // Every error path must produce `intact=false` and a non-empty
        // `reason` — the dashboard surfaces both. A regression that
        // returned `intact=true` with a reason would mislead operators.
        let leaf = Uuid::new_v4();
        let r = err_to_result(leaf, &VerifierError::Decode("bad cbor".into()));
        assert!(!r.intact);
        assert_eq!(r.links_verified, 0);
        assert!(r.p_0.is_none());
        let reason = r.reason.expect("reason present");
        assert!(
            reason.contains("decoding signed PCA bytes"),
            "reason carries Display: {reason}",
        );
        assert!(reason.contains("bad cbor"));
    }

    #[test]
    fn verification_result_serializes_with_stable_wire_field_names() {
        // The dashboard chain-walker keys on every field below — pin
        // the seven-key shape. A serde rename or field reorder would
        // silently break the UI. The `intact + links_verified + p_0 +
        // broken_at + reason + pic_profile + pic_profile_mismatch_at`
        // tuple is the wire contract for `GET /api/v1/pca/{id}/verify`.
        let r = VerificationResult {
            intact: true,
            links_verified: 3,
            p_0: Some("alice@demo.local".into()),
            broken_at: None,
            reason: None,
            pic_profile: Some("proxilion.v1".into()),
            pic_profile_mismatch_at: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        for key in [
            "intact",
            "links_verified",
            "p_0",
            "broken_at",
            "reason",
            "pic_profile",
            "pic_profile_mismatch_at",
        ] {
            assert!(v.get(key).is_some(), "missing wire key: {key}");
        }
        assert_eq!(v["intact"], true);
        assert_eq!(v["links_verified"], 3);
        assert_eq!(v["pic_profile"], "proxilion.v1");
    }

    #[test]
    fn invariant_kind_for_decode_and_missing_matches_bounded_label_set() {
        // The two out-of-contract buckets (`missing`, `decode`, `cat_key`)
        // are explicitly outside spec.md §3.2's named enum but pin them
        // here so a refactor that collapsed them into "unknown" (which
        // would lose chain-walker triage signal — was the row missing
        // from cache, or was its CBOR corrupt?) surfaces as a test
        // failure. The full set is covered in the existing
        // `invariant_kind_labels_are_bounded_and_stable`; this test
        // pins each bucket's distinct label individually to catch a
        // copy-paste that aliased two buckets to the same string.
        assert_ne!(
            invariant_kind(&VerifierError::Missing(Uuid::nil())),
            invariant_kind(&VerifierError::Decode("x".into())),
            "missing and decode must NOT alias",
        );
        assert_ne!(
            invariant_kind(&VerifierError::Decode("x".into())),
            invariant_kind(&VerifierError::CatKey("x".into())),
            "decode and cat_key must NOT alias",
        );
        assert_ne!(
            invariant_kind(&VerifierError::Missing(Uuid::nil())),
            invariant_kind(&VerifierError::CatKey("x".into())),
            "missing and cat_key must NOT alias",
        );
    }

    #[test]
    fn err_to_result_for_hop_order_pins_broken_at_to_leaf_id() {
        // HopOrder carries `{child, parent}` u32 fields, no Uuid — so
        // `err_to_result` falls through to the leaf id. Pin this so
        // a refactor that added a `pca_id` field to HopOrder (the
        // natural fix to make broken_at more precise) would surface
        // here as a wire-shape change rather than as a silently
        // misleading dashboard rendering.
        let leaf = Uuid::new_v4();
        let r = err_to_result(
            leaf,
            &VerifierError::HopOrder {
                child: 5,
                parent: 2,
            },
        );
        assert_eq!(r.broken_at, Some(leaf));
        assert!(!r.intact);
        // The hop integers must surface in the reason for triage.
        let reason = r.reason.expect("reason present");
        assert!(reason.contains('5'));
        assert!(reason.contains('2'));
    }

    #[test]
    fn verifier_error_display_carries_named_field_values() {
        // The `reason` field in VerificationResult is `e.to_string()` —
        // every error variant must surface its named-field values so the
        // dashboard can render them without re-walking the chain. Pin
        // the two structured variants that thiserror's `{field}` syntax
        // is load-bearing for.
        let e = VerifierError::Monotonicity {
            missing: "drive:write:bob/*".into(),
        };
        assert!(e.to_string().contains("drive:write:bob/*"));
        let e = VerifierError::HopOrder {
            child: 3,
            parent: 1,
        };
        let s = e.to_string();
        assert!(s.contains("3"));
        assert!(s.contains("1"));
    }

    #[test]
    fn verifier_error_missing_display_carries_pca_not_found_prefix_and_uuid() {
        // `#[error("pca {0} not found in cache")]` — the operator-facing
        // log substring the chain-walker dashboard keys on. The Uuid
        // renders via its Display (lowercase-hyphenated, NOT the
        // braced Debug form `Uuid("...")`); a refactor to
        // `#[error("pca {0:?} not found ...")]` (the natural
        // "consistent debug formatting" mistake) would silently swap
        // the wire shape and break log filters keyed on the raw uuid
        // substring. Pin both the literal prefix + suffix and the
        // exact uuid Display rendering.
        let id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let e = VerifierError::Missing(id);
        assert_eq!(
            e.to_string(),
            "pca 00112233-4455-6677-8899-aabbccddeeff not found in cache",
        );
    }

    #[test]
    fn verifier_error_bad_cat_signature_display_carries_pca_uuid_and_signature_prefix() {
        // `#[error("CAT signature failed to verify on pca {0}")]` —
        // operators bucket "key rotation drift" (a CAT signature
        // failure on a specific pca) separately from
        // `BadCatSignature`-adjacent variants like `Missing` (which
        // also carries a uuid but indicates the pca itself never
        // arrived in cache). The prefix substring `"CAT signature
        // failed"` is the dashboard key — a "tighten the message"
        // refactor to `"CAT sig failed"` would silently merge the
        // bucket with any future shorter-prefixed CAT-key variant.
        // Pin the full Display shape with a known uuid.
        let id = Uuid::parse_str("deadbeef-0000-0000-0000-000000000001").unwrap();
        let e = VerifierError::BadCatSignature(id);
        assert_eq!(
            e.to_string(),
            "CAT signature failed to verify on pca deadbeef-0000-0000-0000-000000000001",
        );
    }

    #[test]
    fn verifier_error_continuity_broken_display_renders_both_named_uuids_and_full_suffix() {
        // `#[error("continuity broken between pca {child} and predecessor {parent}: provenance.cat_sig mismatch")]`
        // — the only multi-line `thiserror` attribute in the enum
        // (formatted across two source lines). The Display output must
        // be a SINGLE line with both uuids substituted via `{child}` /
        // `{parent}` named-field syntax AND the trailing
        // `": provenance.cat_sig mismatch"` literal preserved (the
        // dashboard keys on the `"provenance.cat_sig"` substring to
        // distinguish a continuity break from a `BadCatSignature`
        // which is also a signature fault but on a different field).
        // A refactor that collapsed the suffix to a generic ": mismatch"
        // would silently merge the two on the wire.
        let child = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let parent = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let e = VerifierError::ContinuityBroken { child, parent };
        assert_eq!(
            e.to_string(),
            "continuity broken between pca 00000000-0000-0000-0000-000000000001 and predecessor 00000000-0000-0000-0000-000000000002: provenance.cat_sig mismatch",
        );
    }

    #[test]
    fn verifier_error_p0_mismatch_display_carries_full_shape_with_both_principals() {
        // `#[error("p_0 changed across hop ({child_p0} != {parent_p0})")]`
        // — pin the parenthesized inequality shape that the
        // dashboard's chain-walker renders verbatim into the
        // "principal mismatch" alert. The asymmetric ordering
        // (child first, parent second) matches the
        // `HopOrder` variant's parameter order so operators can
        // build muscle memory across the two structured variants;
        // a refactor that flipped the ordering "for alphabetical
        // consistency with `child_p0` < `parent_p0`" would silently
        // invert the rendered direction and confuse triage.
        let e = VerifierError::P0Mismatch {
            child_p0: "oidc:alice@example.com".into(),
            parent_p0: "oidc:bob@example.com".into(),
        };
        assert_eq!(
            e.to_string(),
            "p_0 changed across hop (oidc:alice@example.com != oidc:bob@example.com)",
        );
    }

    #[test]
    fn verifier_error_decode_display_carries_decoding_signed_pca_prefix_with_inner_string() {
        // `#[error("decoding signed PCA bytes: {0}")]` — the inner
        // String is built by `SignedPca::from_bytes` and carries the
        // CBOR-decoder's actionable triage message (e.g. "trailing
        // bytes after PCA", "unexpected map key"). The prefix
        // `"decoding signed PCA bytes: "` is what Grafana splits the
        // chain-walker "malformed bytes" bucket on; a refactor to
        // `"decode error: {0}"` would silently merge this with any
        // adjacent decode-style variants. Pin the full prefix-plus-
        // inner-string shape.
        let e = VerifierError::Decode("trailing bytes after PCA terminator".into());
        assert_eq!(
            e.to_string(),
            "decoding signed PCA bytes: trailing bytes after PCA terminator",
        );
    }

    #[test]
    fn verifier_error_cat_key_display_carries_cat_key_fetch_prefix_with_inner_string() {
        // `#[error("CAT key fetch: {0}")]` — the variant the
        // chain-walker emits when the Trust Plane info endpoint or
        // the local CatKeyRegistry lookup fails for a specific kid.
        // Distinct from `BadCatSignature` (which means we HAVE the
        // key but it didn't verify) — the dashboard splits these
        // two on the `"CAT key fetch:"` vs `"CAT signature failed"`
        // substrings, and a refactor that softened either prefix
        // would silently merge "key unavailable" with "key
        // disagreed" on the operator's alert pipeline. Pin the
        // full shape with a known inner message.
        let e = VerifierError::CatKey("kid `cat-2026-Q2` not present in registry".into());
        assert_eq!(
            e.to_string(),
            "CAT key fetch: kid `cat-2026-Q2` not present in registry",
        );
    }
}
