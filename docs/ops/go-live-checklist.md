# Go-live checklist (Production Readiness Review)

> production-readiness.md **PR-13**. Fill this in, sign it, and keep it with
> the deployment record. Nothing here is advisory: **do not expose
> `/oauth/bridge/callback`, or any other IdP-facing route, to an untrusted
> network until every P0 row is checked.**
>
> The engineering-side status of each PR item lives in
> [production-readiness.md](../specs/production-readiness.md); this is the
> *deployment-side* review of one environment.

| Field | Value |
|---|---|
| Environment | |
| Image digest | |
| Chart version | |
| Reviewer | |
| Date | |

## P0 — blocks exposure

- [ ] `PROXILION_ENV=production` and the process **starts**. (If it refuses,
      read the refusal: it names the exact missing setting. Do not work around
      it by dropping to `development`.)
- [ ] `PROXILION_INSECURE_BRIDGE_STUB` is unset or `0`. A forged unsigned
      federation token mints arbitrary authority.
- [ ] `PROXILION_IDP_ISSUER` / `_AUDIENCE` / `_JWKS_URI` are set, and the JWKS
      URI is `https://`.
- [ ] A **tampered** `id_token` presented to `/oauth/bridge/callback` is
      rejected with `401` and a `bridge_rejected` code. *(This is the one test
      worth doing by hand — it is the product's whole thesis.)*
- [ ] `PROXILION_EXECUTOR_KID` **and** `PROXILION_EXECUTOR_KEY` are set, and
      the `kid` is recorded here: ________. Revocation depends on it.
- [ ] TLS material is real (not the dev self-signed cert) and
      `PROXILION_TLS_MIN_VERSION` matches policy.
- [ ] Every secret is mounted via its `*_FILE` path, not an env literal.
- [ ] The token-encryption key is **not** stored where database backups are.
- [ ] `PROXILION_DISABLE_OPERATOR_AUTH` is unset. Operator tokens are issued
      and scoped.
- [ ] `PROXILION_TRUSTED_PROXIES` lists your ingress's peer IPs — or is empty
      because you have no front proxy. Anything else makes the rate-limit key
      spoofable.

## P1 — blocks a real user population

- [ ] ≥ 2 replicas; PodDisruptionBudget present; a rolling restart drops no
      requests.
- [ ] Edge caps sized for the replica count, and `PROXILION_MAX_CONNECTIONS`
      sits below `ulimit -n`.
- [ ] Postgres has WAL archiving and a **tested** restore. Record the drill
      date: ________ and the RTO achieved: ________.
- [ ] `proxilion-cli pic verify-sample` passes against this environment.
- [ ] Prometheus scrapes the proxy; the alert rules are loaded; Alertmanager
      routes `page` to a pager someone is actually carrying.
- [ ] `proxilion_pca_verify_failures_total` reads **zero**, and the alert on
      it is confirmed to route to the security receiver.
- [ ] Every on-call has the [runbooks](./runbooks/README.md) and knows where
      the killswitch is.
- [ ] The policy bundle has been through observe mode and its blocks reviewed.
- [ ] Approvals reach a real human — Slack or email — and the reviewer's
      justification lands on the audit row.

## P2 — before you call it GA

- [ ] Image and CLI signatures verified at install
      ([verifying-artifacts.md](../install/verifying-artifacts.md)).
- [ ] Key rotation rehearsed ([key-rotation.md](./runbooks/key-rotation.md)).
- [ ] Killswitch drill executed ([killswitch.md](./runbooks/killswitch.md)).
- [ ] Load test at target rate across ≥ 2 replicas; capacity numbers recorded
      in [ha-and-scaling.md](./ha-and-scaling.md).
- [ ] External security assessment scheduled or complete.

## Sign-off

> I have verified every P0 row against this environment, not against a
> document.

| Role | Name | Date |
|---|---|---|
| Deploying engineer | | |
| Security reviewer | | |

## Known-accepted risks

Record anything you are going live without, and who accepted it. An empty
table is a claim that nothing was waived.

| Item | Why accepted | Accepted by | Review date |
|---|---|---|---|
| | | | |
