# Runbook — Key compromise & emergency rotation

> Critical procedure (security incident). A leaked signing/encryption secret.
> Full secret inventory, blast radius, and in-memory hygiene live in
> [key-inventory.md](../key-inventory.md) — read it first; this runbook is the
> *response*. Severity matrix: [SECURITY.md](../../../SECURITY.md). Rotation
> overlap mechanics: production-readiness.md PR-3.

## Declare and scope

Treat any of the following as a confirmed compromise: a secret committed to
version control, present in a leaked backup/log, exfiltrated from a node, or
exposed by a dependency CVE. Open the
[IC checklist](./incident-response.md) immediately — key compromise is a
security incident, not a routine rotation.

Identify **which** secret and its blast radius from
[key-inventory.md](../key-inventory.md):

| Secret | If leaked, the attacker can… | First containment |
|---|---|---|
| **Token-encryption key** (`PROXILION_TOKEN_ENCRYPTION_KEY`) | decrypt **every** stored upstream OAuth token → impersonate every linked user against the SaaS | rotate key **and** force upstream-token re-consent; assume all stored tokens are burned |
| **SIEM HMAC key** (`PROXILION_SIEM_HMAC_KEY`) | forge SIEM event signatures (tamper the feed your SOC trusts) | rotate; re-establish trust with the SOC; review recent SIEM events for forgery |
| **Blocked-webhook HMAC key** (`PROXILION_BLOCKED_WEBHOOK_HMAC_KEY`) | forge blocked-action webhook signatures | rotate; distrust webhook deliveries in the exposure window |
| **Ingress TLS private key** (`PROXILION_TLS_KEY`) | impersonate / MITM the proxy endpoint | reissue cert (cert-manager), **revoke** the old cert, rotate key |
| **Trust Plane CAT key** (Helm `secret.yaml`) | mint/forge PCA chains (forge authority) | Trust-Plane-owned rotation; until done, treat chain signatures as suspect — escalate to the Trust Plane owner |

## Emergency rotation — token-encryption key (worked example)

This is the highest-blast-radius secret and the only one that protects data at
rest, so it gets the fullest procedure.

1. **Provision the new key** in the secret store (External Secrets / Vault /
   KMS mount). Honor the `*_FILE` convention — point
   `PROXILION_TOKEN_ENCRYPTION_KEY_FILE` at the new mount; never bake the key
   into an image or env literal.
2. **Re-wrap stored ciphertext.** Stored upstream tokens are encrypted under
   the old key. Until versioned-key overlap ships (PR-3), rotation requires a
   re-encrypt pass: stand up with the old key, decrypt-then-re-encrypt every
   `google_tokens` row under the new key (the planned `proxilion-cli` re-wrap
   helper; until it lands, a maintenance-window script under the old+new key
   pair), then flip the active key. **If the old key is already burned**, you
   cannot re-wrap — invalidate the stored tokens and force every user through a
   fresh OAuth consent.
3. **Flip and drain.** Set the new key active, keep the old key as
   *also-accept* for the drain window (versioned overlap, PR-3), then retire
   the old key. With today's single-key path, the flip is a coordinated
   restart after the re-wrap completes.
4. **Verify:** a stored token encrypted pre-rotation decrypts post-rotation
   (re-wrap path), or all sessions re-consented (burn path); no decrypt errors
   in logs; `/healthz` ready.

## Emergency rotation — HMAC keys (SIEM / blocked-webhook)

Stateless signers — no stored ciphertext to re-wrap, so rotation is a
key-swap + restart:

1. Write the new key to the secret store (`*_FILE` preferred).
2. Restart replicas to pick it up. Consumers (SOC SIEM, webhook receiver) must
   be updated with the new key **in lockstep** — coordinate the cutover so
   in-flight deliveries aren't dropped as "bad signature."
3. Treat every signature produced under the leaked key during the exposure
   window as **untrusted**; tell the SOC/receiver to discard or re-verify.

## Audit-chain continuity

Rotating Proxilion's keys does **not** invalidate the historical audit chain:
each persisted PCA records the `kid`/PIC profile it was signed under
(`spec.md` §15.11), so a verifier selects the correct key by version. After any
rotation, sample-verify across the rotation boundary —
`proxilion-cli pic verify <leaf-id>` for a chain whose links straddle old and
new keys must still return `intact:true`.

## Post-incident

- Confirm the leaked secret is invalid everywhere (no replica, backup, or
  cached config still serves it).
- Record the exposure window, blast radius, and remediation in the incident
  record; if user OAuth tokens were in scope, follow the disclosure SLA in
  [SECURITY.md](../../../SECURITY.md).
- File the gap that caused the leak (e.g. missing `*_FILE` mount → key in env)
  as a tracked issue.

**Drill log:** _rehearse the token-key re-wrap and one HMAC swap in staging
with zero rejected in-flight requests (PR-3 acceptance) — not yet executed._
