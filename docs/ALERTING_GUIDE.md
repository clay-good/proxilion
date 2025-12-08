# Alerting Configuration Guide

This guide explains how to configure Prometheus alerts for Proxilion MCP Security Gateway.

---

## Overview

Proxilion exports 30+ Prometheus metrics at the `/metrics` endpoint. This guide covers:
1. Available metrics reference
2. Recommended alert rules
3. Alert routing configuration
4. Integration with notification systems
5. Tuning alerts to reduce noise

---

## Available Metrics

### Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_requests_total` | Counter | `decision` | Total analysis requests |
| `proxilion_requests_by_user_total` | Counter | `user_id` | Requests per user |

### Threat Detection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_threats_detected_total` | Counter | `analyzer`, `decision` | Threats by analyzer |
| `proxilion_threats_blocked_total` | Counter | `analyzer` | Blocked threats |
| `proxilion_threat_score` | Histogram | `analyzer` | Score distribution |
| `proxilion_patterns_detected_total` | Counter | `pattern_type` | Detected patterns |
| `proxilion_gtg1002_indicators_total` | Counter | `indicator_type` | GTG-1002 indicators |

### Performance Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_analysis_duration_seconds` | Histogram | `analyzer` | Per-analyzer latency |
| `proxilion_total_analysis_duration_seconds` | Histogram | - | End-to-end latency |

### Session Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_active_sessions` | Gauge | - | Current active sessions |
| `proxilion_sessions_created_total` | Counter | `user_id` | Sessions created |
| `proxilion_sessions_terminated_total` | Counter | `reason` | Sessions terminated |

### Analyzer Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_analyzer_invocations_total` | Counter | `analyzer` | Analyzer runs |
| `proxilion_analyzer_errors_total` | Counter | `analyzer` | Analyzer errors |

### Semantic Analysis Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_semantic_analysis_requests_total` | Counter | `analyzer`, `result` | Claude API calls |
| `proxilion_semantic_analysis_cost_usd` | Counter | `analyzer` | API cost (USD) |
| `proxilion_prompt_cache_hits_total` | Counter | `analyzer` | Cache hits |
| `proxilion_prompt_cache_misses_total` | Counter | `analyzer` | Cache misses |
| `proxilion_prompt_cache_cost_saved_usd` | Counter | `analyzer` | Cost savings |

### Health Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxilion_gateway_up` | Gauge | - | Gateway health (1=up) |
| `proxilion_redis_connected` | Gauge | - | Redis status (1=connected) |
| `proxilion_errors_total` | Counter | `error_type` | Error counts |

---

## Alert Rules Configuration

Create the following file as `alerts.yml` in your Prometheus configuration directory.

### alerts.yml

```yaml
groups:
  #############################################################################
  # CRITICAL ALERTS - Require immediate response
  #############################################################################
  - name: proxilion_critical
    interval: 30s
    rules:
      # Session terminated - highest severity threat
      - alert: ProxilionSessionTerminated
        expr: increase(proxilion_sessions_terminated_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Proxilion session terminated due to threat"
          description: "{{ $value }} session(s) terminated in the last 5 minutes. Reason: {{ $labels.reason }}. Immediate investigation required."
          runbook: "https://docs/INCIDENT_RESPONSE.md#critical-score-90-session-terminated"

      # High threat score activity burst
      - alert: ProxilionHighThreatBurst
        expr: increase(proxilion_threats_detected_total{decision="Terminate"}[5m]) > 3
        for: 0m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Multiple high-severity threats detected"
          description: "{{ $value }} terminate-level threats detected in 5 minutes. Possible active attack."
          runbook: "https://docs/INCIDENT_RESPONSE.md#multi-phase-attack-chain-kill-chain"

      # Gateway down
      - alert: ProxilionGatewayDown
        expr: proxilion_gateway_up == 0
        for: 1m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Proxilion gateway is down"
          description: "Proxilion gateway has been down for more than 1 minute. Security monitoring is offline."
          runbook: "https://docs/TROUBLESHOOTING.md#gateway-down"

      # Redis connection lost
      - alert: ProxilionRedisDown
        expr: proxilion_redis_connected == 0
        for: 2m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Proxilion lost Redis connection"
          description: "Redis connection lost for 2+ minutes. Session tracking disabled."
          runbook: "https://docs/TROUBLESHOOTING.md#redis-connection-lost"

  #############################################################################
  # HIGH ALERTS - Respond within 4 hours
  #############################################################################
  - name: proxilion_high
    interval: 60s
    rules:
      # Blocked threats increasing
      - alert: ProxilionThreatsBlocked
        expr: increase(proxilion_threats_blocked_total[15m]) > 5
        for: 5m
        labels:
          severity: high
          team: security
        annotations:
          summary: "Multiple threats blocked"
          description: "{{ $value }} threats blocked in the last 15 minutes. Analyzer: {{ $labels.analyzer }}."
          runbook: "https://docs/INCIDENT_RESPONSE.md#medium-score-70-89-blocked"

      # Credential access attempts
      - alert: ProxilionCredentialAccess
        expr: increase(proxilion_threats_detected_total{analyzer="credential"}[15m]) > 0
        for: 0m
        labels:
          severity: high
          team: security
        annotations:
          summary: "Credential access attempt detected"
          description: "Credential harvesting attempt detected. Decision: {{ $labels.decision }}."
          runbook: "https://docs/INCIDENT_RESPONSE.md#credential-harvesting-attempt"

      # Data exfiltration attempts
      - alert: ProxilionExfiltrationAttempt
        expr: increase(proxilion_threats_detected_total{analyzer="exfiltration"}[15m]) > 0
        for: 0m
        labels:
          severity: high
          team: security
        annotations:
          summary: "Data exfiltration attempt detected"
          description: "Data exfiltration attempt detected. Decision: {{ $labels.decision }}."
          runbook: "https://docs/INCIDENT_RESPONSE.md#data-exfiltration-attempt"

      # GTG-1002 indicators
      - alert: ProxilionGTG1002Indicator
        expr: increase(proxilion_gtg1002_indicators_total[30m]) > 0
        for: 0m
        labels:
          severity: high
          team: security
        annotations:
          summary: "GTG-1002 attack indicator detected"
          description: "Indicator type: {{ $labels.indicator_type }}. This matches patterns of sophisticated AI-orchestrated attacks."
          runbook: "https://docs/INCIDENT_RESPONSE.md#multi-phase-attack-chain-kill-chain"

      # High error rate
      - alert: ProxilionHighErrorRate
        expr: rate(proxilion_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: high
          team: platform
        annotations:
          summary: "Proxilion experiencing high error rate"
          description: "Error rate: {{ $value | printf \"%.2f\" }}/sec. Error type: {{ $labels.error_type }}."
          runbook: "https://docs/TROUBLESHOOTING.md#high-error-rate"

  #############################################################################
  # MEDIUM ALERTS - Review within 24 hours
  #############################################################################
  - name: proxilion_medium
    interval: 120s
    rules:
      # Alert-level threats
      - alert: ProxilionAlertThreats
        expr: increase(proxilion_threats_detected_total{decision="Alert"}[1h]) > 10
        for: 15m
        labels:
          severity: medium
          team: security
        annotations:
          summary: "Elevated alert-level threats"
          description: "{{ $value }} alert-level threats in the last hour. May indicate suspicious activity or need for threshold tuning."

      # Network reconnaissance
      - alert: ProxilionReconnaissance
        expr: increase(proxilion_threats_detected_total{analyzer="enumeration"}[1h]) > 3
        for: 0m
        labels:
          severity: medium
          team: security
        annotations:
          summary: "Network reconnaissance activity"
          description: "{{ $value }} reconnaissance attempts detected. Could indicate scanning or authorized security testing."

      # High latency
      - alert: ProxilionHighLatency
        expr: histogram_quantile(0.95, rate(proxilion_total_analysis_duration_seconds_bucket[5m])) > 0.1
        for: 10m
        labels:
          severity: medium
          team: platform
        annotations:
          summary: "Proxilion analysis latency elevated"
          description: "P95 latency: {{ $value | printf \"%.3f\" }}s. Target: <50ms."

      # Single user high activity
      - alert: ProxilionUserHighActivity
        expr: increase(proxilion_requests_by_user_total[1h]) > 1000
        for: 0m
        labels:
          severity: medium
          team: security
        annotations:
          summary: "Single user with high request volume"
          description: "User {{ $labels.user_id }} made {{ $value }} requests in 1 hour. May be automated or compromised."

      # Semantic analysis cost spike
      - alert: ProxilionSemanticCostHigh
        expr: increase(proxilion_semantic_analysis_cost_usd[1h]) > 10
        for: 0m
        labels:
          severity: medium
          team: platform
        annotations:
          summary: "Semantic analysis cost elevated"
          description: "Spent ${{ $value | printf \"%.2f\" }} on Claude API in the last hour."

  #############################################################################
  # LOW ALERTS - Review in weekly report
  #############################################################################
  - name: proxilion_low
    interval: 300s
    rules:
      # General threat activity
      - alert: ProxilionThreatActivity
        expr: increase(proxilion_threats_detected_total[24h]) > 50
        for: 0m
        labels:
          severity: low
          team: security
        annotations:
          summary: "Elevated threat detection rate"
          description: "{{ $value }} total threats detected in 24 hours."

      # Analyzer errors
      - alert: ProxilionAnalyzerErrors
        expr: increase(proxilion_analyzer_errors_total[1h]) > 5
        for: 0m
        labels:
          severity: low
          team: platform
        annotations:
          summary: "Analyzer errors detected"
          description: "{{ $value }} errors from {{ $labels.analyzer }} analyzer."

      # Low prompt cache hit rate (cost inefficiency)
      - alert: ProxilionLowCacheHitRate
        expr: |
          rate(proxilion_prompt_cache_hits_total[1h])
          / (rate(proxilion_prompt_cache_hits_total[1h]) + rate(proxilion_prompt_cache_misses_total[1h]))
          < 0.5
        for: 1h
        labels:
          severity: low
          team: platform
        annotations:
          summary: "Semantic analysis cache hit rate low"
          description: "Cache hit rate {{ $value | printf \"%.1f\" }}%. Expected >50% for cost efficiency."
```

---

## Prometheus Configuration

Update your `prometheus.yml` to load the alert rules:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'proxilion-mcp-gateway'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - "alerts.yml"

scrape_configs:
  - job_name: 'proxilion-gateway'
    static_configs:
      - targets: ['gateway:8787']
    metrics_path: '/metrics'
    scrape_interval: 5s
    scrape_timeout: 3s

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Alertmanager Configuration

Configure Alertmanager to route alerts to appropriate channels.

### alertmanager.yml

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: 'default'
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

  routes:
    # Critical alerts - immediate notification
    - match:
        severity: critical
      receiver: 'critical-alerts'
      group_wait: 0s
      repeat_interval: 15m

    # High alerts - security team
    - match:
        severity: high
        team: security
      receiver: 'security-team'
      repeat_interval: 1h

    # High alerts - platform team
    - match:
        severity: high
        team: platform
      receiver: 'platform-team'
      repeat_interval: 1h

    # Medium alerts
    - match:
        severity: medium
      receiver: 'security-team'
      repeat_interval: 4h

    # Low alerts - daily digest
    - match:
        severity: low
      receiver: 'daily-digest'
      group_wait: 1h
      repeat_interval: 24h

receivers:
  - name: 'default'
    webhook_configs:
      - url: 'http://localhost:5001/webhook'

  - name: 'critical-alerts'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
        severity: critical
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#security-critical'
        title: 'CRITICAL: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  - name: 'security-team'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#security-alerts'
        title: '{{ .GroupLabels.severity | toUpper }}: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
    email_configs:
      - to: 'security-team@company.com'
        from: 'proxilion-alerts@company.com'
        smarthost: 'smtp.company.com:587'

  - name: 'platform-team'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#platform-alerts'

  - name: 'daily-digest'
    email_configs:
      - to: 'security-team@company.com'
        from: 'proxilion-alerts@company.com'
        smarthost: 'smtp.company.com:587'
        send_resolved: false

inhibit_rules:
  # If gateway is down, suppress other alerts
  - source_match:
      alertname: 'ProxilionGatewayDown'
    target_match_re:
      alertname: 'Proxilion.*'
    equal: ['instance']

  # If Redis is down, suppress session-related alerts
  - source_match:
      alertname: 'ProxilionRedisDown'
    target_match_re:
      alertname: 'ProxilionSession.*'
```

---

## Integration Examples

### Slack Integration

1. Create a Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Create a webhook for your alerts channel
4. Add the webhook URL to alertmanager.yml

### PagerDuty Integration

1. Create a service in PagerDuty
2. Add a Prometheus integration
3. Copy the integration key to alertmanager.yml
4. Configure escalation policies in PagerDuty

### Email Integration

```yaml
email_configs:
  - to: 'security-team@company.com'
    from: 'proxilion-alerts@company.com'
    smarthost: 'smtp.company.com:587'
    auth_username: 'alerts@company.com'
    auth_password: 'your-smtp-password'
    require_tls: true
```

### Webhook Integration (Custom)

```yaml
webhook_configs:
  - url: 'https://your-internal-system.com/alerts'
    send_resolved: true
    http_config:
      bearer_token: 'your-api-token'
```

---

## Alert Tuning

### Reducing False Positives

If you're getting too many alerts:

1. **Increase thresholds** for count-based alerts:
   ```yaml
   expr: increase(proxilion_threats_blocked_total[15m]) > 10  # was 5
   ```

2. **Add longer duration requirements**:
   ```yaml
   for: 15m  # was 5m
   ```

3. **Filter specific analyzers** if they're noisy:
   ```yaml
   expr: increase(proxilion_threats_detected_total{analyzer!="enumeration"}[15m]) > 5
   ```

4. **Adjust time windows** for bursty patterns:
   ```yaml
   expr: increase(proxilion_threats_blocked_total[30m]) > 10  # was 15m
   ```

### Reducing Alert Noise

1. **Group similar alerts**:
   ```yaml
   group_by: ['alertname', 'analyzer']
   ```

2. **Increase repeat interval**:
   ```yaml
   repeat_interval: 12h  # was 4h
   ```

3. **Use inhibit rules** to suppress redundant alerts

4. **Create daily digests** for low-severity alerts

### Recommended Baseline Tuning Period

| Week | Mode | Action |
|------|------|--------|
| 1 | Monitor | Collect baseline, all alerts to low severity |
| 2 | Monitor | Analyze false positive rate, adjust thresholds |
| 3 | Alert | Enable medium/high severity routing |
| 4 | Block | Enable critical alerts with paging |

---

## Grafana Dashboard Queries

### Threat Detection Rate

```promql
sum(rate(proxilion_threats_detected_total[5m])) by (decision)
```

### Top Triggering Analyzers

```promql
topk(5, sum(increase(proxilion_threats_detected_total[1h])) by (analyzer))
```

### P95 Latency

```promql
histogram_quantile(0.95, rate(proxilion_total_analysis_duration_seconds_bucket[5m]))
```

### Threat Score Distribution

```promql
histogram_quantile(0.50, rate(proxilion_threat_score_bucket[1h]))
histogram_quantile(0.90, rate(proxilion_threat_score_bucket[1h]))
histogram_quantile(0.99, rate(proxilion_threat_score_bucket[1h]))
```

### Session Termination Rate

```promql
sum(rate(proxilion_sessions_terminated_total[1h])) by (reason)
```

### Semantic Analysis Cost

```promql
sum(increase(proxilion_semantic_analysis_cost_usd[24h]))
```

---

## Testing Alerts

### Verify Alert Rules Load

```bash
# Check Prometheus rules
curl http://localhost:9090/api/v1/rules | jq '.data.groups[].rules[].name'
```

### Trigger Test Alert

```bash
# Send high-threat request to trigger alert
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {"Bash": {"command": "nmap -sV 10.0.0.0/24", "args": [], "env": {}}},
    "user_id": "test@company.com",
    "session_id": "test-alert-123"
  }'
```

### Check Alert Status

```bash
# View firing alerts
curl http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | {alertname: .labels.alertname, state: .state}'
```

### Verify Alertmanager Receives

```bash
# Check Alertmanager
curl http://localhost:9093/api/v1/alerts | jq '.[].labels.alertname'
```

---

## Troubleshooting Alerts

### Alerts Not Firing

1. Check Prometheus can scrape metrics:
   ```bash
   curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
   ```

2. Verify rule syntax:
   ```bash
   promtool check rules alerts.yml
   ```

3. Check rule evaluation:
   ```bash
   curl "http://localhost:9090/api/v1/query?query=ALERTS"
   ```

### Alerts Not Reaching Alertmanager

1. Verify Alertmanager is running:
   ```bash
   curl http://localhost:9093/-/healthy
   ```

2. Check Prometheus alertmanager config:
   ```bash
   curl http://localhost:9090/api/v1/alertmanagers
   ```

### Notifications Not Sending

1. Check Alertmanager logs:
   ```bash
   docker logs alertmanager 2>&1 | grep -i error
   ```

2. Verify webhook/email credentials

3. Test notification channel directly

---

## Next Steps

1. Copy `alerts.yml` to your Prometheus config directory
2. Update `prometheus.yml` to load the rules
3. Configure Alertmanager with your notification channels
4. Run in monitor mode for 1 week to tune thresholds
5. Enable critical alerts first, then gradually enable others
