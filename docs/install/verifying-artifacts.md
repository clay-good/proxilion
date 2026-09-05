# Verifying what you downloaded

Proxilion's release artifacts are signed and carry build provenance so you can
confirm **what** is inside them and **that this project's CI built them**
(production-readiness.md PR-10 / PR-11). Verify before you deploy.

## Proxy container image (cosign keyless)

The proxy image is multi-arch, Trivy-scanned, **cosign-keyless-signed**, and
ships SLSA provenance + an SBOM attestation
([image workflow](../../.github/workflows/image.yml)).

```sh
IMG=ghcr.io/clay-good/proxilion-proxy@sha256:<digest>   # digest from the release

# Signature + identity (must be this repo's image workflow):
cosign verify "$IMG" \
  --certificate-identity-regexp 'https://github.com/clay-good/proxilion/.github/workflows/image.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SBOM + SLSA provenance attestations:
cosign download sbom "$IMG"
cosign verify-attestation --type slsaprovenance "$IMG" \
  --certificate-identity-regexp 'https://github.com/clay-good/proxilion/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pin the verified digest in Helm: `proxy.image.digest: sha256:<digest>`
(see the [chart README](../../deploy/helm/proxilion/README.md)).

## `proxilion-cli` binary (GitHub attestations)

The CLI release binaries carry SLSA build provenance via GitHub artifact
attestations ([release workflow](../../.github/workflows/release.yml)). After
downloading + extracting the `.tar.gz` from the GitHub Release:

```sh
# Checksums are published alongside each archive:
sha256sum -c proxilion-cli-<target>.tar.gz.sha256

# Verify the binary's provenance (built by this repo's release workflow):
gh attestation verify ./proxilion-cli --repo clay-good/proxilion
```

`gh attestation verify` confirms the binary was produced by the
`clay-good/proxilion` release workflow on a GitHub-hosted runner — a forged or
tampered binary fails verification.

## Release archives + SBOMs (cosign keyless)

Every `.tar.gz` on the Release, and every SBOM next to it, is signed with
cosign keyless — no key material, the signature is bound to this repo's
release workflow identity. Each signed file has a `.cosign.bundle` beside it
carrying the signature, the Fulcio certificate and the Rekor inclusion proof
together, so verification is one command rather than three downloads:

```sh
cosign verify-blob proxilion-cli-<target>.tar.gz \
  --bundle proxilion-cli-<target>.tar.gz.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/clay-good/proxilion/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The `--certificate-identity-regexp` is the part that matters: without it you
have proved only that *somebody* signed the file through Sigstore.

## SBOMs

A CycloneDX 1.5 SBOM is attached per workspace crate
(`proxilion-cli-<tag>.cdx.json`, `proxy-<tag>.cdx.json`, and the two library
crates). It lists every dependency with its version and license, so "am I
affected by CVE-X" is a `jq` away:

```sh
jq -r '.components[] | select(.name=="openssl") | .version' proxy-v0.1.0.cdx.json
```

The dependency set comes from `Cargo.lock`, so one SBOM describes the source
graph every target was built from (modulo platform-conditional crates). Verify
the SBOM itself with the same `cosign verify-blob` command as above.

## Not shipped: `cargo auditable` embedding

Dependency data is **not** embedded inside the CLI binaries, so
`cargo audit bin proxilion-cli` will report an incomplete graph. The release
build goes through `taiki-e/upload-rust-binary-action`, which fixes the build
tool to `cargo`/`cross`/`cargo-zigbuild`; `cargo auditable` must wrap the build
command and cannot be injected through `RUSTC_WORKSPACE_WRAPPER` (it refuses to
run as a rustc wrapper). Embedding it would mean hand-rolling the
cross-compilation, archiving and checksum steps that action provides — a real
reliability regression for information the attached SBOM already carries. Use
the SBOM.
