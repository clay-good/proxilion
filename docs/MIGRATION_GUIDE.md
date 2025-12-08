# Migration Guide

This guide covers migrating to Proxilion MCP Security Gateway from existing security solutions or greenfield deployments.

---

## Overview

Proxilion operates at the **MCP orchestration layer** - a position that traditional security tools don't cover. This means Proxilion typically **complements** rather than **replaces** your existing security stack.

**Key understanding**: Proxilion is not a replacement for:
- Endpoint Detection and Response (EDR)
- Web Application Firewalls (WAF)
- SIEM/log aggregation
- Network security appliances

It fills a gap that didn't exist before AI coding assistants became prevalent.

---

## Migration Scenarios

### Scenario 1: Greenfield (No Existing AI Security)

**Current state**: Using Claude Code, Copilot, Cursor, or Windsurf without any MCP-layer security.

**Migration steps**:

1. Deploy Proxilion in monitor mode:
   ```bash
   docker compose up -d
   # MODE=monitor is the default
   ```

2. Configure your MCP clients to route through Proxilion (see [examples/](../examples/))

3. Run for 1-2 weeks in monitor mode to:
   - Establish baseline behavior
   - Identify false positives for your workflow
   - Tune thresholds if needed

4. Review logs and metrics:
   ```bash
   # Check what would have been blocked
   curl http://localhost:8787/metrics | grep threat_score
   ```

5. Transition to alert mode:
   ```bash
   # Update docker-compose.yml or environment
   MODE=alert docker compose up -d
   ```

6. After 1 week with alerts functioning correctly, enable blocking:
   ```bash
   MODE=block docker compose up -d
   ```

**Timeline**: 2-4 weeks from start to full blocking.

---

### Scenario 2: From Manual Code Review Policies

**Current state**: Relying on manual code review or PR approval processes to catch malicious AI-generated code.

**Why migrate**: Manual review cannot catch attacks in real-time. By the time a human reviews the code, the attack may already have executed.

**Migration steps**:

1. Identify which AI assistants are in use across your organization

2. Deploy Proxilion in monitor mode

3. Configure each AI assistant to route through Proxilion:
   - [Claude Code configuration](../examples/claude-code/)
   - [Cursor configuration](../examples/cursor/)
   - [Windsurf configuration](../examples/windsurf/)

4. Keep existing code review processes in place - Proxilion is additive, not a replacement for code review

5. Gradually transition high-risk operations to block mode while keeping monitor mode for lower-risk workflows

**Key difference**: Proxilion prevents execution before code review would even see the change. They serve different purposes.

---

### Scenario 3: From Custom Regex/Script Blockers

**Current state**: Using custom bash scripts, regex filters, or home-grown solutions to block dangerous commands.

**Why migrate**:
- Custom solutions lack session correlation (can't detect multi-phase attacks)
- No semantic analysis for obfuscated commands
- Maintenance burden
- No observability/metrics

**Migration steps**:

1. Document your existing regex patterns and blocked commands

2. Review Proxilion's built-in analyzers to confirm coverage:
   ```bash
   # See crates/threat-engine/src/analyzers/ for all patterns
   ls crates/threat-engine/src/analyzers/
   ```

3. Identify any custom patterns not covered by Proxilion

4. For uncovered patterns, consider:
   - Opening a GitHub issue to request the pattern
   - Running Proxilion alongside your existing solution temporarily

5. Deploy Proxilion in monitor mode and compare detection rates

6. Once satisfied with coverage, disable custom solution and enable Proxilion blocking

**What you gain**:
- 24+ battle-tested analyzers
- Session-aware detection (kill chain tracking)
- Prometheus metrics and Grafana dashboards
- Lower maintenance burden

**What you lose**:
- Any highly customized patterns specific to your environment (may need to request additions)

---

### Scenario 4: From Enterprise DLP Solutions

**Current state**: Using Data Loss Prevention (DLP) tools like Symantec, Digital Guardian, or Forcepoint.

**Why add Proxilion**: DLP operates at the endpoint or network layer - it sees data after it's been staged. Proxilion sees the AI's intent before data is accessed.

**Migration steps**:

1. **Do not remove DLP** - Proxilion and DLP serve different purposes

2. Deploy Proxilion alongside existing DLP

3. Configure alert integration to feed Proxilion alerts into your existing DLP/SIEM workflow:
   ```yaml
   # In alertmanager.yml
   receivers:
     - name: 'dlp-integration'
       webhook_configs:
         - url: 'https://your-dlp-api/webhook'
   ```

4. Map Proxilion threat categories to your DLP policy categories:

   | Proxilion Pattern | DLP Category |
   |-------------------|--------------|
   | credential_access | Sensitive Data |
   | exfiltration | Data Transfer |
   | enumeration | Reconnaissance |

5. Tune false positive thresholds to match your DLP sensitivity levels

**Architecture**:
```
AI Assistant
    |
    v
Proxilion (blocks malicious intent)
    |
    v
MCP Server (executes command)
    |
    v
DLP Agent (monitors data access)
    |
    v
SIEM (aggregates all alerts)
```

---

### Scenario 5: From EDR/XDR Solutions

**Current state**: Using CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, or similar EDR.

**Why add Proxilion**: EDR sees commands after they execute. Proxilion blocks before execution.

**Example**:
```
Without Proxilion:
1. AI runs: nmap -sV 192.168.1.0/24
2. nmap executes (network scan happens)
3. EDR detects nmap process
4. Alert fires (damage already done)

With Proxilion:
1. AI attempts: nmap -sV 192.168.1.0/24
2. Proxilion blocks (HTTP 403)
3. nmap never executes
4. Alert fires (zero damage)
```

**Migration steps**:

1. **Do not remove EDR** - keep as defense-in-depth

2. Deploy Proxilion in monitor mode

3. Configure Proxilion to send alerts to your EDR/SIEM:
   ```bash
   # Prometheus metrics can be scraped by most SIEMs
   curl http://localhost:8787/metrics
   ```

4. Create correlation rules in your SIEM to link Proxilion blocks with any EDR alerts that still fire (indicates the block failed or was bypassed)

5. Run both in parallel for 2-4 weeks to validate detection overlap

6. Enable Proxilion blocking - your EDR becomes the safety net for anything Proxilion misses

---

## Configuration Migration

### From Environment Variables

If you have existing configuration in environment variables, Proxilion uses similar patterns:

| Common Pattern | Proxilion Equivalent |
|----------------|---------------------|
| `SECURITY_MODE=permissive` | `MODE=monitor` |
| `SECURITY_MODE=warn` | `MODE=alert` |
| `SECURITY_MODE=enforce` | `MODE=block` |
| `SECURITY_MODE=strict` | `MODE=terminate` |
| `BLOCK_THRESHOLD=0.7` | `BLOCK_THRESHOLD=70` |
| `REDIS_HOST=redis` | `REDIS_URL=redis://redis:6379` |

### From YAML Configuration Files

Proxilion does not use YAML config files - all configuration is via environment variables. Convert your existing YAML to env vars:

```yaml
# Old config.yaml
security:
  mode: block
  thresholds:
    alert: 0.5
    block: 0.7
  redis:
    host: redis
    port: 6379
```

```bash
# New environment variables
MODE=block
ALERT_THRESHOLD=50
BLOCK_THRESHOLD=70
REDIS_URL=redis://redis:6379
```

### From JSON Policy Files

If migrating from a JSON-based policy system:

```json
// Old policy.json
{
  "rules": [
    {"pattern": "nmap.*", "action": "block"},
    {"pattern": "cat.*\\.env", "action": "alert"}
  ]
}
```

Proxilion has these patterns built-in. No policy file needed. To verify coverage:

```bash
# Check enumeration patterns
grep -r "nmap" crates/threat-engine/src/analyzers/

# Check credential access patterns
grep -r "\.env" crates/threat-engine/src/analyzers/
```

---

## Data Migration

### Session History

Proxilion's session-aware analyzers benefit from historical data but do not require it. On first deployment:

- Sessions start fresh with no history
- Kill chain detection begins tracking from first request
- Request rate baselines are established over time

If you have historical session data from another system, it cannot be imported - Proxilion uses its own session format in Redis.

### Alert History

Historical alerts cannot be imported. Proxilion maintains its own:
- Prometheus metrics (time-series data)
- PostgreSQL analytics (if configured)
- Grafana dashboards (visualization)

To preserve historical context, keep your old alerting system running alongside Proxilion during the transition period.

### Allowlists/Blocklists

Proxilion does not currently support custom allowlists via configuration. If you have existing allowlists:

1. Document which patterns are allowed in your current system
2. Review if those patterns would trigger Proxilion alerts in monitor mode
3. If legitimate patterns are blocked:
   - Adjust threshold values
   - Open a GitHub issue to discuss allowlist feature
   - Consider running in alert mode instead of block mode for affected patterns

---

## Rollback Procedures

### Emergency Rollback

If Proxilion causes issues in production:

```bash
# Option 1: Switch to monitor mode (immediate, keeps logging)
MODE=monitor docker compose up -d

# Option 2: Bypass Proxilion entirely
# Update your MCP client config to point directly to MCP servers
# Remove PROXILION_GATEWAY environment variables

# Option 3: Stop Proxilion
docker compose down
```

### Gradual Rollback

If detection rates are too aggressive:

1. Lower thresholds:
   ```bash
   ALERT_THRESHOLD=60  # Was 50
   BLOCK_THRESHOLD=80  # Was 70
   ```

2. Switch problematic workflows to alert mode while keeping block mode for high-risk operations

3. Review false positives and adjust

---

## Integration Checklist

Before considering migration complete:

- [ ] All AI assistants routed through Proxilion
- [ ] Monitor mode run for 1+ week
- [ ] False positive rate acceptable (<5%)
- [ ] Alerts integrated with existing SIEM/ticketing
- [ ] Incident response procedures updated for Proxilion alerts
- [ ] Security team trained on interpreting Proxilion alerts
- [ ] Rollback procedure documented and tested
- [ ] Prometheus metrics being collected
- [ ] Grafana dashboards configured (if using monitoring stack)
- [ ] Block mode enabled for production workloads

---

## Common Migration Issues

### Issue: High False Positive Rate

**Symptom**: Legitimate developer operations flagged as threats.

**Solution**:
1. Stay in monitor mode longer to understand baseline
2. Increase `BLOCK_THRESHOLD` (e.g., 80 instead of 70)
3. Review flagged patterns - some may be legitimate security testing
4. Consider separate configurations for security teams vs. general developers

### Issue: Session Correlation Not Working

**Symptom**: Multi-phase attacks not detected; each request analyzed in isolation.

**Solution**:
1. Verify clients are sending consistent `session_id` values
2. Check Redis connectivity: `redis-cli ping`
3. Verify `SESSION_STORE=redis` is set (not `inmemory`)

### Issue: High Latency After Migration

**Symptom**: AI assistant responses slower than before Proxilion.

**Solution**:
1. Check P95 latency: should be <50ms
2. Verify Redis latency: `redis-cli --latency`
3. Disable semantic analysis if not needed: `ENABLE_SEMANTIC_ANALYSIS=false`
4. Check network path between AI assistant and Proxilion

### Issue: Alerts Not Reaching SIEM

**Symptom**: Proxilion detects threats but alerts don't appear in your SIEM.

**Solution**:
1. Verify Prometheus is scraping `/metrics`
2. Check Alertmanager configuration
3. Verify webhook URLs are correct
4. Test with manual alert trigger

---

## Support

For migration assistance:
- GitHub Issues: https://github.com/clay-good/proxilion/issues
- Documentation: See [docs/](../docs/) directory

---

## Summary

| Migration From | Recommended Approach | Timeline |
|----------------|---------------------|----------|
| Nothing (greenfield) | Deploy monitor -> alert -> block | 2-4 weeks |
| Manual review | Add Proxilion, keep reviews | 1-2 weeks |
| Custom scripts | Replace after validation | 2-3 weeks |
| DLP | Add alongside, integrate alerts | 1-2 weeks |
| EDR | Add alongside, correlate alerts | 1-2 weeks |

Proxilion is designed to be adopted incrementally. Start with monitor mode, prove value, then enforce.
