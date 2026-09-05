# Runbook — Planned key rotation

> The scheduled procedure, one section per secret. For a **leaked** key go to
> [key-compromise.md](./key-compromise.md) instead — the two are genuinely
> different, and the difference is the point (see below). Full inventory and
> blast radius: [key-inventory.md](../key-inventory.md).

**Why planned and emergency rotation are different procedures.** A planned
rotation keeps the old key accepted for a drain window so nothing in flight is
rejected. That window is exactly what you must *not* grant a leaked key: the
attacker's copy works for as long as the proxy accepts it. Overlap buys zero
downtime; it does not buy containment.

**Cadence.** Annually for every secret below, and always after a person with
access to it leaves. TLS is cert-manager's cadence, not yours.

## Which secrets support overlap

| Secret | Overlap? | Why |
|---|---|---|
| Token-encryption key | **Yes** — active + up to 4 retired decrypt keys | It protects data *at rest*, so both keys are ours to hold |
| PIC executor seed | No (roll to the new `kid`) | The Trust Plane registry is the coordination point |
| CAT verifying key | N/A — fetched, not held | Refreshed on a 1 h TTL; a rotation lands on its own |
| SIEM / blocked-webhook HMAC | No | These sign **outbound** bodies; the *receiver* is what must trust both keys, so it is a coordinated cutover by construction |
| Ingress TLS key | cert-manager | Standard cert rotation, overlapping by certificate validity |

## 1. Token-encryption key (zero downtime)

The only rotation that is genuinely seamless. Full mechanism and rationale in
[key-inventory.md](../key-inventory.md#rotating-the-token-encryption-key-zero-downtime);
the operational sequence:

```bash
NEW=$(openssl rand -hex 32)     # write to the secret store, not your shell history
```

1. **Add.** `PROXILION_TOKEN_ENCRYPTION_KEY` ← new key;
   `PROXILION_TOKEN_ENCRYPTION_KEYS_PREVIOUS` ← old key. Roll the fleet.
2. **Drain.** Watch `proxilion_token_decrypt_total{key="previous"}`. Stored
   rows re-encrypt themselves as upstream tokens refresh; rows that never
   refresh expire with their session.
3. **Retire.** When the `previous` series stops incrementing, clear
   `PROXILION_TOKEN_ENCRYPTION_KEYS_PREVIOUS`, roll again, and destroy the old
   key material.

**Verify:** `proxilion_token_decrypt_total{key="failed"}` stays at zero
throughout, and an agent request that uses a stored upstream token succeeds
after step 3.

**If the drain stalls,** you have long-lived rows whose sessions never
refresh. Either wait out the session TTL or revoke those sessions
([killswitch.md](./killswitch.md)) — do not clear the previous key while the
`previous` series is still moving, or those rows become undecryptable.

## 2. PIC executor seed

No overlap: the Trust Plane holds one registration per `kid`, and the whole
reason the `kid` is stable is so a specific executor can be revoked.

1. Generate a new seed and a **new `kid`** (`proxy-prod-2`). Both change
   together — reusing the `kid` with new material would have replicas
   registering different public keys under one name during the roll.
2. Set `PROXILION_EXECUTOR_KID` + `PROXILION_EXECUTOR_KEY` and roll. Replicas
   register the new executor on first use.
3. Once the fleet is fully rolled, have the Trust Plane retire the old `kid`.

**Verify:** new action events carry the new executor `kid`, and
`proxilion-cli pic verify-sample` still returns every chain intact — the
historical chain signed under the old `kid` must keep verifying (each PCA
records the `kid` it was signed under).

## 3. SIEM / blocked-webhook HMAC keys

Coordinated cutover with the receiver; there is no proxy-side overlap that
helps, because the receiver is the verifier.

1. Agree a cutover instant with the SOC / webhook owner.
2. Configure the receiver to accept **both** keys (most SIEMs support this; if
   yours does not, you need a maintenance window).
3. Swap `PROXILION_SIEM_HMAC_KEY` / `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY` and
   roll.
4. Have the receiver drop the old key.

**Verify:** deliveries in the cutover window are accepted, not logged as bad
signatures, on the receiver's side.

## 4. CAT verifying key

Nothing to do on the proxy. It fetches the Trust Plane's CAT public key and
caches it for one hour, so a Trust-Plane-side rotation reaches every replica
within the hour on its own. A failing refresh keeps serving the last key for
at most one more hour and then fails closed, so a rotation performed while the
Trust Plane is unreachable will surface as verification failures rather than
as silently honoring a retired key.

**Verify:** `proxilion-cli trust-plane info` shows the new `kid`, and a chain
verification across the rotation boundary still returns `intact:true`.

## 5. Ingress TLS key

cert-manager rotation; see [tls-mtls-matrix.md](../tls-mtls-matrix.md). The
proxy loads TLS material at boot, so a renewed certificate needs a pod roll —
the `ProxilionCertExpirySoon` alert is the reminder that this has to happen
before expiry, not after.

## Drill log

*(placeholder — PR-3 acceptance)*

| Date | Secret | Downtime | Rejected requests | Notes |
|---|---|---|---|---|
| — | — | — | — | not yet executed against a staging stand-up |

The acceptance criterion is a token-encryption-key rotation completed in
staging with **zero** rejected in-flight requests.
