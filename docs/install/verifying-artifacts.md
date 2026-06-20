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

## Still open (PR-10)

CycloneDX SBOMs attached to the GitHub Release, `cargo auditable` dependency
data embedded in the shipped binaries, and cosign signatures on the `.tar.gz`
archives are tracked follow-ups; the image (above) already carries SBOM +
provenance + signature today.
