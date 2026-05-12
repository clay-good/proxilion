# Proxilion reference demo

Four scenarios, ~90 seconds end-to-end. Authority: [`spec.md`](../docs/specs/spec.md) §4.4.

## What it shows

| # | Script | What it proves |
|---|---|---|
| 1 | [`01-pic-chain-walk.sh`](scripts/01-pic-chain-walk.sh) | A real PCA_0 is minted; chain inspection works. |
| 2 | [`02-confused-deputy.sh`](scripts/02-confused-deputy.sh) | **The headline.** An attempt to mint a successor with ops outside the predecessor's grant is refused by the Trust Plane. Non-expressible by construction. |
| 3 | [`03-blocked-override.sh`](scripts/03-blocked-override.sh) | A Layer-B policy block on a gmail send → operator approves with justification → override PCA chains from PCA_0. |
| 4 | [`04-killswitch.sh`](scripts/04-killswitch.sh) | Per-session killswitch revokes the bearer; subsequent requests fail at the middleware. |

## Run it

```bash
# From repo root.
./demo/run.sh
```

`run.sh` brings up the docker compose stack (postgres + trust-plane + mock-okta + nats + proxy), checks `/healthz`, then runs all four scenarios in order, printing what's happening at each step.

## Prereqs

- Docker + Docker Compose
- `jq`, `curl`, `uuidgen`, `xxd`, `openssl` — standard on macOS and most Linux distros

## What you'll observe in scenario 2

```
▶ Mint PCA_0: alice@demo.local can read her own files + engineering
  p_0=user:http://127.0.0.1:9090/default#alice@demo.local
  ops=drive:read:alice@demo.local, drive:read:engineering

▶ Seed a synthetic blocked action that attempts ESCALATION

▶ Attempting override (attacker tries to bypass)…
{"error":"pic_invariant_violation",
 "detail":"ops not subset of predecessor: missing drive:write:bob/finance/secret.docx"}

✓ Trust Plane refused with HTTP 422 — monotonicity invariant held.
  ops 'drive:write:bob/finance/secret.docx' is NOT a subset of PCA_0.ops
  The successor was never minted. No chain exists for the attempt.

▶ Confirm: the override PCA was never persisted
  successor PCAs chained from PCA_0: 0 (expected 0)

✓ Confused-deputy attack non-expressible by construction.
```

That's the unique value of Proxilion stated as a script.

## Tear down

```bash
docker compose down -v
```

## Going deeper

- **NATS action stream:**
  ```bash
  docker run --rm --network proxilion-dev_default natsio/nats-box:latest \
    nats -s nats://nats:4222 sub 'actions.>'
  ```
- **CLI tail:** `cargo run -p proxilion-cli -- actions tail --endpoint https://127.0.0.1:8443 --insecure`
- **Prometheus metrics:** `curl -sk https://127.0.0.1:8443/metrics`
- **Helm chart:** [`deploy/helm/proxilion`](../deploy/helm/proxilion/) — `helm lint` + `helm template` clean.

## Why not a wiremock'd Google?

The two attack scenarios that matter (confused-deputy refusal at the Trust Plane, and Layer-B block + override) are observable *without* a real Google upstream — they happen before the egress call. A wiremock'd Google adds noise to the demo without changing the proof. When we add an integration-test harness that runs the adapter happy path, we'll wire wiremock in there, not here.
