# Email notifier — SMTP / DMARC / SPF / DKIM

Closes [ui-less-surfaces.md §11 open question #3](../specs/ui-less-surfaces.md).

Proxilion's email notifier (`ui-less-surfaces.md §5.4`) hands off
delivery to a customer-configured SMTP relay. We deliberately do not
sign messages on the proxy — DKIM signing belongs at the relay, which
is the only place the customer's keys live. Below are three known-good
configurations.

The principle in all three:

- The `From:` address used by Proxilion must match (or be authorized
  by) the relay's SPF / DKIM domain. Operators get this wrong about
  half the time on the first attempt.
- DMARC alignment requires *either* SPF *or* DKIM to align — both are
  better, but one suffices. SES, Postmark, SendGrid, and Mailgun all
  default to DKIM-aligned delivery once the domain is verified in the
  relay's UI.
- The `notifier_config.email.from` value Proxilion uses lives in the
  DB. Rotate it via `proxilion-cli notifier set-email --from ...`.

---

## 1. AWS SES (recommended for AWS-hosted deployments)

```bash
proxilion-cli notifier set-email \
    --smtp-url "smtps://AKIA...:<smtp-pass>@email-smtp.us-east-1.amazonaws.com:465" \
    --from "Proxilion <secops@acme.com>" \
    --to "secops-oncall@acme.com"
```

Domain setup in SES console:

1. **Verified identity** → add the domain (`acme.com`).
2. SES surfaces three CNAME records for DKIM. Drop them into Route 53
   (or any DNS provider) and wait for verification.
3. Optionally add the SPF include: `v=spf1 include:amazonses.com -all`
   to your domain's TXT record. With DKIM verified, DMARC aligns
   without this — keep it as a defence-in-depth measure.
4. **DMARC**: TXT at `_dmarc.acme.com` —
   `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@acme.com`.

SMTP credentials are *not* your IAM access key — use **SMTP
credentials** generated under "Account dashboard → SMTP settings."

---

## 2. Postmark (recommended for outbound-only setups)

```bash
proxilion-cli notifier set-email \
    --smtp-url "smtp://<server-api-token>:<server-api-token>@smtp.postmarkapp.com:587" \
    --from "Proxilion <secops@acme.com>" \
    --to "secops-oncall@acme.com"
```

Notes:

- Postmark uses the same token as the username AND password.
- Sender Signatures must be verified per `From:` address. For a
  domain-wide signature, use Postmark's "Sender Signatures →
  Domain" flow — generates the DKIM `DomainKey` CNAME you publish.
- Postmark refuses to deliver until DMARC alignment is verified;
  this surfaces fast in the dashboard.
- The proxy's lettre client supports both port 587 (STARTTLS) and
  port 465 (implicit TLS). Postmark accepts both.

---

## 3. Internal Postfix / Exim relay (recommended for self-hosted)

```bash
proxilion-cli notifier set-email \
    --smtp-url "smtp://proxilion:<relay-pass>@mail.internal.acme.com:587" \
    --from "Proxilion <secops@acme.com>" \
    --to "secops-oncall@acme.com"
```

For the relay itself:

- **Postfix**: add the proxy's network range to `mynetworks`; or
  configure SASL auth and create a `proxilion` user.
- **OpenDKIM**: sign outbound on the relay side. Generate a keypair,
  publish the public-key TXT at `default._domainkey.acme.com`, and
  configure OpenDKIM to sign `From: secops@acme.com`. Proxilion never
  sees the private key.
- **SPF**: include the relay's IP range in your domain's SPF record.
- **DMARC**: same TXT record as the SES section above.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Mail delivered but lands in spam | DMARC failing | Verify SPF *or* DKIM aligns with the `From:` domain. |
| Relay rejects with 530 / 535 | Bad SMTP credentials | Confirm `smtp_url` user:pass; use `proxilion-cli notifier config` to re-read. |
| Proxy log: `smtp_transient_exhausted` | Relay timeout / 4xx after retries | Check relay reachability from the proxy's pod / box. |
| Proxy log: `smtp_permanent` | Hard reject (auth / bad recipient) | Inspect the recipient + sender; SES "sandbox" mode refuses unverified recipients. |
| `From:` rejected as "not authorized" | Sender Signature missing | Add the address (or whole domain) to the relay's verified identities. |

For the metric story, `proxilion_email_send_total{kind,result}` and
`proxilion_email_send_failures_total{reason}` tick on every send —
graph these in your Grafana to alert on `transient_exhausted` rate.

---

## What Proxilion deliberately does NOT do

- **DKIM signing on the proxy side.** Keys belong at the relay.
- **Bounce-handling.** The relay's webhook / bounce queue is the
  source of truth for "did the operator actually receive it." Add a
  separate notifier (Webhook driver) pointing at the SES SNS topic or
  Postmark bounce webhook if you need to react to bounces.
- **List management.** Proxilion sends to a fixed set of recipients
  per policy (`notifier_recipients`) or the global default. No
  subscribe/unsubscribe surface — these are internal security
  notifications, not marketing email.
