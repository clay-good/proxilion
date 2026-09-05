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
| **PIC executor seed** (`PROXILION_EXECUTOR_KEY`) | mint successor PCAs *as this proxy* — forge the custody chain for any authority a predecessor already carries | rotate the seed **and** the `kid`, and have the Trust Plane revoke the old executor registration; the old `kid` is what makes revocation possible at all |
| **Trust Plane CAT key** (Helm `secret.yaml`) | mint/forge PCA chains (forge authority) | Trust-Plane-owned rotation; until done, treat chain signatures as suspect — escalate to the Trust Plane owner. Proxy replicas pick up the new CAT key within the 1 h verifying-key TTL, no fleet roll needed |

## Emergency rotation — token-encryption key (worked example)

This is the highest-blast-radius secret and the only one that protects data at
rest, so it gets the fullest procedure.

**A compromised key is not a planned rotation.** The planned procedure
([key-rotation.md](./key-rotation.md)) keeps the old key accepted for
decryption while stored rows drain onto the new one. You cannot do that here:
leaving the leaked key in
`PROXILION_TOKEN_ENCRYPTION_KEYS_PREVIOUS` means the attacker's copy still
decrypts everything the proxy can. The overlap mechanism buys you an ordering
choice, not an exposure window.

1. **Provision the new key** in the secret store (External Secrets / Vault /
   KMS mount). Honor the `*_FILE` convention — point
   `PROXILION_TOKEN_ENCRYPTION_KEY_FILE` at the new mount; never bake the key
   into an image or env literal.
2. **Decide: re-wrap, or burn.**
   - **Re-wrap** (the leaked key is not yet being used by anyone else, and you
     accept a short window): set the new key active with the leaked key in
     `PROXILION_TOKEN_ENCRYPTION_KEYS_PREVIOUS`, roll, force every
     `google_tokens` row to re-encrypt under the new key, then **immediately**
     clear the previous-key list and roll again. Keep this window in minutes,
     not the hours a planned drain would take.
   - **Burn** (default, and mandatory if the key may already be in use):
     rotate with **no** overlap. Every stored upstream token becomes
     undecryptable, which is the correct outcome — those tokens are
     compromised. Invalidate the sessions and force a fresh OAuth consent.
3. **Verify:** `proxilion_token_decrypt_total{key="previous"}` reads zero
   after you clear the overlap (re-wrap path), or all sessions re-consented
   (burn path); no decrypt errors in logs; `/healthz` ready.

## Emergency rotation — PIC executor seed

The executor key signs Proofs of Custody, so a leak lets the attacker mint
successor PCAs as this proxy.

1. Generate a new seed (`openssl rand -hex 32`) **and a new `kid`** — reusing
   the `kid` would leave the Trust Plane unable to distinguish the compromised
   registration from the replacement.
2. Update `PROXILION_EXECUTOR_KEY` (prefer the `_FILE` mount) and
   `PROXILION_EXECUTOR_KID` together, and roll the fleet. Setting only one is
   refused at boot in a protected environment.
3. Have the Trust Plane **revoke the old executor registration**. This is the
   step the whole stable-identity requirement exists for: an ephemeral
   per-replica key would leave nothing specific to revoke.
4. Treat every PoC signed under the leaked seed during the exposure window as
   suspect and review the affected chains.

## Emergency rotation — HMAC keys (SIEM / blocked-webhook)

Stateless signers — no stored ciphertext to re-wrap, so rotation is a
key-swap + restart. Note that these keys sign **outbound** bodies, so no
amount of proxy-side overlap helps: the accepting side is what has to trust
both keys, which makes this a coordinated cutover by construction.

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

**Drill log:** _rehearse the token-key burn path and one HMAC swap in staging
(PR-3 acceptance) — not yet executed. The planned-rotation drill lives in
[key-rotation.md](./key-rotation.md)._
