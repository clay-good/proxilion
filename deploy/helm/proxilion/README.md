# proxilion Helm chart

Production-shaped chart for Proxilion. Authority: [`docs/specs/spec.md`](../../../docs/specs/spec.md) §4.2.

## What this chart deploys

- **proxy** — the Proxilion reverse proxy itself. TLS-terminating axum
  server on port 8443. Replicas configurable; HPA optional.
- **trust-plane** — upstream `provenance-plane` (binary from
  [`clay-good/provenance`](https://github.com/clay-good/provenance)). One
  replica today; multi-replica once federation lands.
- **nats** — optional event bus for the action-stream fan-out
  (spec.md §3.1). Disable with `--set nats.enabled=false`.

## What this chart does NOT deploy

- **Postgres** — connect to a managed instance via `postgres.externalUrl`
  *and* by setting `database-url` in the secret. The chart never bundles
  a database — every customer already has one they trust.
- **Ingress controller / cert-manager / external-secrets** — assumed
  pre-installed. The chart only renders an `Ingress` and a `ServiceMonitor`
  when explicitly enabled.
- **Federation Bridge** — deferred upstream (see spec.md §0.4 Status).
  Trust Plane currently accepts JWTs directly.

## Quickstart

```bash
# 1. Create the secret out-of-band.
kubectl create namespace proxilion
kubectl -n proxilion create secret generic proxilion-secrets \
  --from-literal=database-url='postgres://proxilion:PASS@db:5432/proxilion' \
  --from-literal=token-encryption-key=$(openssl rand -hex 32) \
  --from-literal=trust-plane-cat-key=$(openssl rand -hex 32) \
  --from-literal=google-client-id='YOUR_CLIENT_ID' \
  --from-literal=google-client-secret='YOUR_CLIENT_SECRET'

# 2. Install.
helm install proxilion ./deploy/helm/proxilion \
  --namespace proxilion \
  --set postgres.externalUrl='postgres://db:5432/proxilion' \
  --set proxy.env.customerDomain='acme.com' \
  --set proxy.ingress.enabled=true \
  --set proxy.ingress.hosts[0].host='proxy.acme.com' \
  --set proxy.ingress.hosts[0].paths[0].path='/' \
  --set proxy.ingress.hosts[0].paths[0].pathType='Prefix'
```

## Validating the chart locally

```bash
helm lint ./deploy/helm/proxilion
helm template proxilion ./deploy/helm/proxilion \
  --set secrets.existingSecret='proxilion-secrets' \
  --set postgres.externalUrl='postgres://db/proxilion' \
  > /tmp/proxilion.yaml
kubectl apply --dry-run=client -f /tmp/proxilion.yaml
```

## Production guidance

- **CAT signing key is the trust root for PIC.** Pre-create it in your KMS
  or HSM and mount it via `secrets.existingSecret`. Don't generate it from
  the chart in production.
- **OAuth client credentials.** Each Google Workspace customer typically
  uses one OAuth client per Proxilion deployment. Document the
  redirect URI required by Google: `https://<host>/oauth/google/callback`.
- **`runAsNonRoot: true`, `readOnlyRootFilesystem: true`.** Defaults are
  hardened; do not loosen unless you have a documented reason.
- **HPA.** Enable for any deployment that handles real agent traffic;
  the proxy is CPU-bound under load (TLS termination + COSE signing).
- **Network policies.** Apply NetworkPolicies in the namespace so only
  the agent-platform ingress can reach the proxy, only the proxy can
  reach Postgres + Trust Plane, etc. The chart does not render these
  by default because every customer's cluster mesh is different.

## Verifying & pinning the proxy image

The proxy image is built multi-arch (amd64 + arm64) from a **distroless,
non-root** base by the [`image`](../../../.github/workflows/image.yml) release
workflow, which Trivy-scans it (gating on fixable HIGH/CRITICAL), signs it with
**cosign keyless** (Sigstore), and attaches **SLSA build provenance + an SBOM**.
The workflow prints the published digest.

```sh
# Verify the signature + provenance (keyless, bound to this repo's CI):
cosign verify ghcr.io/clay-good/proxilion-proxy@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/clay-good/proxilion/.github/workflows/image.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Inspect the attached SBOM / provenance attestations:
cosign download sbom ghcr.io/clay-good/proxilion-proxy@sha256:<digest>
```

**Pin by digest in production:** set `proxy.image.digest: sha256:<digest>`
(supersedes `proxy.image.tag`) so every replica runs the exact, signed image.
