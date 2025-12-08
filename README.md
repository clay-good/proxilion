# Proxilion MCP Security Gateway

Real-time threat detection for AI coding assistants. Analyzes MCP tool calls to detect insider threats, compromised accounts, and rogue AI agents before they can weaponize Claude Code, GitHub Copilot, Cursor, or Windsurf.

---

## What This Is

Proxilion is a Rust-based security gateway that sits between AI assistants and MCP servers. It analyzes every tool call (bash commands, file operations, network requests) for malicious patterns before execution.

**What it does well:**
- Pattern-based threat detection (credential harvesting, network reconnaissance, data exfiltration)
- Session correlation (tracks multi-phase attack chains)
- Low latency analysis (<50ms P95 in benchmarks)
- Custom policy DSL for rules, allowlists, blocklists
- 358 tests passing

**What it does NOT do:**
- Prevent attacks that don't involve MCP tool calls
- Detect novel attack patterns not in its ruleset
- Provide authentication (you must deploy behind an auth layer)
- Guarantee detection of sophisticated attackers

---

## Quick Start

### Docker Deployment

```bash
git clone https://github.com/clay-good/proxilion
cd proxilion

# Start in monitor mode (logs only, never blocks)
docker compose up -d

# Check health
curl http://localhost:8787/health

# View metrics
curl http://localhost:8787/metrics
```

### Build from Source

```bash
cargo build --release

# Run with in-memory session store (testing only)
SESSION_STORE=inmemory MODE=monitor ./target/release/proxilion-gateway

# Run with Redis (production)
SESSION_STORE=redis REDIS_URL=redis://localhost:6379 MODE=block ./target/release/proxilion-gateway
```

### Enable Monitoring Stack

```bash
docker compose --profile monitoring up -d
```

- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090

---

## Architecture

```
AI Assistant (Claude Code, Copilot, etc.)
        |
        v
Proxilion Gateway (analyzes tool call, <50ms)
        |
        v
Decision: Allow | Alert | Block | Terminate
        |
        v
MCP Server executes (or rejects) the tool call
```

### Components

| Crate | Purpose |
|-------|---------|
| `gateway` | HTTP API server (Axum), request routing, operational modes |
| `threat-engine` | 22 pattern-based analyzers + 2 session-aware analyzers |
| `session-state` | Redis/In-Memory/PostgreSQL session storage |
| `mcp-protocol` | MCP JSON-RPC 2.0 parsing |

### Threat Analyzers (24 Active in Pipeline)

**Pattern-Based (22):**
- Enumeration (nmap, masscan, port scanning)
- Credential Access (.env, SSH keys, AWS credentials, /etc/shadow)
- Exfiltration (curl to external IPs, pastebin uploads, netcat)
- AI Velocity (automated execution patterns)
- Prompt Engineering (jailbreak attempts)
- Social Engineering (authority claims, roleplay manipulation)
- Callback Validation (C2 detection, SSRF)
- MCP Orchestration (malicious MCP chaining)
- File Access (sensitive file patterns)
- Task Fragmentation (command chaining, obfuscation)
- Data Volume (bulk transfers, database dumps)
- Privilege Escalation (sudo abuse, SUID)
- Lateral Movement (SSH pivoting, internal network)
- Hacking Tools (metasploit, hashcat, mimikatz)
- Hallucination (AI fabrication detection)
- Persistence (cron jobs, systemd, backdoors)
- Defense Evasion (log clearing, firewall bypass)
- Command and Control (reverse shells, Cobalt Strike)
- Collection (data staging, screenshots)
- Impact (destructive operations like rm -rf)
- Tool Call (SQL injection, command chaining)
- Legitimacy (context-aware false positive reduction)

**Session-Aware (2):**
- Request Rate (burst detection, machine-like velocity)
- Session Progression (kill chain tracking: Recon -> Credentials -> Exfiltration)

**Additional Analyzers (6, require explicit configuration):**
- AI Autonomy (autonomous agent detection)
- Conversation Analysis (social engineering via conversation context)
- Conversation Context (multi-turn tracking)
- Multi-Target Orchestration (parallel target operations)
- Multi-User Correlation (coordinated attacks across users)
- Semantic Analysis (Claude API-based intent analysis, optional feature flag)

---

## Configuration

### Environment Variables

```bash
# Required
MODE=monitor                # monitor | alert | block | terminate
SESSION_STORE=redis         # inmemory | redis
REDIS_URL=redis://localhost:6379

# Optional
LISTEN_ADDR=0.0.0.0:8787
ALERT_THRESHOLD=50
BLOCK_THRESHOLD=70
TERMINATE_THRESHOLD=90

# Policy file (optional, for custom rules)
POLICY_FILE=./proxilion-policy.toml

# Semantic Analysis (optional, requires Claude API)
ENABLE_SEMANTIC_ANALYSIS=false
ANTHROPIC_API_KEY=sk-ant-xxx
```

### Custom Policy DSL

Define custom rules, allowlists, and blocklists in a TOML file:

```bash
# Copy example and customize
cp proxilion-policy.example.toml proxilion-policy.toml

# Run with policy
POLICY_FILE=./proxilion-policy.toml ./target/release/proxilion-gateway
```

Example policy rules:

```toml
# proxilion-policy.toml

[settings]
alert_threshold = 50
block_threshold = 70

# Allow git operations
[[rules]]
name = "allow-git"
pattern = "^git (status|log|diff|commit)"
action = "allow"
priority = 100

# Block reverse shells
[[rules]]
name = "block-reverse-shell"
pattern = "bash -i >& /dev/tcp"
action = "block"
score = 95

# Security team can use nmap
[[rules]]
name = "security-nmap"
pattern = "nmap"
action = "allow"
[rules.conditions]
user_pattern = "security-.*@company.com"

# Allowlist for specific users
[[allowlists.users]]
id = "security-team@company.com"
bypass_patterns = ["nmap", "metasploit"]

# Blocklist dangerous commands
[[blocklists.commands]]
pattern = "rm -rf /"
reason = "Destructive command"
score = 100
```

See [proxilion-policy.example.toml](proxilion-policy.example.toml) for a complete example.

### Operational Modes

| Mode | Score < 50 | Score 50-69 | Score 70-89 | Score >= 90 |
|------|------------|-------------|-------------|-------------|
| `monitor` | Allow + Log | Allow + Log | Allow + Log | Allow + Log |
| `alert` | Allow | Allow + Alert | Allow + Alert | Allow + Alert |
| `block` | Allow | Alert | **Block** | **Block** |
| `terminate` | Allow | Alert | **Block** | **Block + Terminate Session** |

---

## API Reference

### POST /analyze

Analyze a tool call for threats.

**Request:**
```json
{
  "tool_call": {
    "Bash": {
      "command": "nmap -sV target.com",
      "args": [],
      "env": {}
    }
  },
  "user_id": "user@company.com",
  "session_id": "session_123"
}
```

**Response:**
```json
{
  "decision": "Block",
  "threat_score": 88.0,
  "patterns": [
    "nmap reconnaissance tool detected",
    "Port scanning flags detected"
  ],
  "session_terminated": false,
  "session_id": "session_123"
}
```

**Status Codes:**
- `200 OK` - Analysis complete (Allow or Alert)
- `403 Forbidden` - Blocked or Terminated
- `500 Internal Server Error` - Gateway error

### GET /health

Health check endpoint.

### GET /metrics

Prometheus metrics export.

---

## Integration Examples

**Note:** Client libraries are included in this repository but not yet published to npm/PyPI. Install from local source:

```bash
# TypeScript - install from local package
cd packages/mcp-proxilion-middleware && npm install && npm run build
npm link  # or copy to your project

# Python - install from local package
cd packages/proxilion-mcp-python && pip install -e .
```

### TypeScript

```typescript
import { ProxilionMCPClient } from '@proxilion/mcp-middleware';

const client = new ProxilionMCPClient({
  proxilionEndpoint: 'http://localhost:8787',
  userId: 'user@company.com',
  mode: 'block',
});

const result = await client.callToolWithAnalysis(toolCall, executeFunc);
```

### Python

```python
from proxilion_mcp import ProxilionMCPClient, ProxilionConfig

client = ProxilionMCPClient(ProxilionConfig(
    proxilion_endpoint="http://localhost:8787",
    user_id="user@company.com",
    mode="block",
))

result = await client.call_tool_with_analysis(tool_call, execute_func)
```

See [examples/](examples/) for complete integration code.

See [examples/cursor/](examples/cursor/) and [examples/windsurf/](examples/windsurf/) for IDE-specific integration guides.

**Note:** Cursor and Windsurf do not natively support MCP proxy configuration. The integration guides provide workarounds (network-level proxies, MCP wrappers) that have limitations. See the individual guides for details.

---

## Limitations (Read This)

### This is NOT a Silver Bullet

Proxilion is one layer in defense-in-depth. It will not catch everything.

### Architectural Constraints

1. **MCP-layer only**: We only see tool calls. If an attacker manipulates the AI without triggering tool execution, we cannot detect it.

2. **Pattern-based detection**: We detect known attack patterns. Novel techniques, custom obfuscation, or attacks not in our ruleset may evade detection.

3. **No authentication**: Proxilion does not verify user identity. You MUST deploy behind an authentication layer (API gateway, reverse proxy with OAuth/OIDC).

4. **Requires persistent session IDs**: Clients must provide consistent `session_id` values. Without this, session-aware analyzers (kill chain detection, request rate) cannot function.

5. **False positives exist**: Legitimate security work (penetration testing, DevOps) may trigger alerts. Expect to tune thresholds for your environment. Target <5% false positive rate.

### What We Cannot Detect

1. **Strategic planning before tool calls**: Social engineering that succeeds before any tool is executed (e.g., attacker convinces AI to help, but hasn't executed anything yet).

2. **Custom orchestration above MCP**: Attacker frameworks coordinating multiple AI instances externally.

3. **Attacks fragmented over months**: If individual requests appear benign in isolation, session correlation won't help.

4. **Non-MCP AI systems**: We only protect MCP-compatible tools.

5. **Direct network attacks**: We analyze tool calls, not network packets. A direct SSH brute-force bypasses us entirely.

6. **Obfuscated commands**: Heavy base64 encoding, variable expansion tricks, or polyglot payloads may evade pattern matching.

7. **Insider with legitimate access**: If an authorized user with real credentials decides to exfiltrate data using normal tools in normal ways, detection is difficult.

### Operational Constraints

1. **Semantic analysis costs money**: If enabled, Claude API calls cost approximately $0.0015 per analyzed request. At 100,000 requests/month, that's $150/month. Only runs for ambiguous scores (40-80 range).

2. **Redis required for production**: In-memory session store is for testing only. Session data is lost on restart.

3. **Cold start latency**: First request after startup may take 100-200ms as analyzers initialize.

4. **No admin UI**: All configuration is via environment variables and TOML policy files. No web dashboard.

5. **Limited to single-instance**: No built-in clustering. Scale horizontally by running multiple instances behind a load balancer (each needs access to shared Redis).

6. **No failover testing**: Redis and PostgreSQL failover scenarios have not been tested. Plan for data loss during infrastructure failures.

7. **No security audit**: This codebase has not undergone independent security audit or penetration testing. Use at your own risk in high-security environments.

8. **Regex patterns not fuzzed**: Pattern matching regexes have not been fuzz-tested. Malformed input could potentially cause unexpected behavior.

9. **TLS not enforced**: Gateway accepts HTTP connections. You must configure TLS at the reverse proxy or load balancer level.

10. **Redis authentication not enforced**: Gateway connects to Redis without requiring authentication. You must configure Redis `requirepass` separately.

### Detection Rate Claims

The "75-85% detection rate against GTG-1002-class attacks" claim:
- Based on internal testing against a specific attack scenario
- Not independently validated
- Real-world detection rates depend heavily on attacker sophistication and your tuning
- Novel attacks will have lower detection rates until patterns are added

### What's Missing

- Built-in rate limiting at gateway level (use external rate limiter like NGINX or Kong)
- Published npm/PyPI packages (client libraries must be installed from local source)
- Helm charts for Kubernetes deployment
- Native IDE plugins (Cursor, Windsurf, VS Code) - workarounds only

### Known Evasion Limitations

The following bypass techniques are documented in the evasion test suite but not fully mitigated:

- Variable concatenation (`a=nm;b=ap;$a$b`) - command built dynamically
- Nested command substitution (`$($(echo echo) nmap)`)
- Printf hex escapes (`$(printf '\\x6e\\x6d\\x61\\x70')`)
- Wildcard credential access (`cat /home/*/.ssh/id_*`) - read-only heuristic bypass

---

## Security Considerations

### Deploy Behind Authentication

Proxilion does NOT authenticate users. Deploy architecture:

```
Client (with auth token)
    |
    v
API Gateway / Reverse Proxy (OAuth, API key validation)
    |
    v
Proxilion Gateway (threat analysis)
    |
    v
MCP Server (tool execution)
```

### Best Practices

- Network isolation (private VPC, security groups)
- TLS/SSL for all connections
- Redis authentication enabled (requirepass)
- Secrets management (Vault, AWS Secrets Manager)
- Resource limits (Docker memory/CPU constraints)
- Regular log review and alerting

### Vulnerability Reporting

Open a GitHub issue or contact maintainers directly.

---

## Testing

```bash
# Run all tests (358 tests)
cargo test

# Run unit tests only
cargo test -p threat-engine --test unit_tests

# Run evasion bypass tests
cargo test -p threat-engine --test evasion_tests

# Run demo attack simulation
./demo.sh

# Run performance benchmarks (requires criterion.rs)
cargo bench -p threat-engine

# Run specific benchmark
cargo bench -p threat-engine -- analyze_safe

# Run load tests (requires k6: brew install k6)
k6 run loadtest/baseline.js

# Run stress test
k6 run loadtest/stress.js
```

## Tools

### Cost Calculator

Estimate monthly costs for semantic analysis:

```bash
# Build and run
cd tools && cargo build --release
./target/release/cost-calculator --requests 100000

# With custom parameters
./target/release/cost-calculator -r 500000 -a 0.25 -c 0.50

# Show comparison table
./target/release/cost-calculator --compare
```

Example output:
```
PROXILION SEMANTIC ANALYSIS COST ESTIMATE
═══════════════════════════════════════════════════════════════
Monthly requests:             100,000
Ambiguous rate:                  30.0%
Result cache hit rate:           40.0%

TOTAL MONTHLY COST:            $64.06
Cost per request:           $0.000641
```

---

## Production Checklist

Before deploying to production:

- [ ] Run in monitor mode for 1+ week to establish baseline
- [ ] Review false positive rate (target: <5%)
- [ ] Configure Redis with authentication
- [ ] Set up Prometheus + Grafana monitoring
- [ ] Configure alerts for high threat scores (70+)
- [ ] Deploy behind authentication layer
- [ ] Enable TLS/SSL
- [ ] Test fail-open vs fail-closed behavior for your use case
- [ ] Document incident response procedures for your team
- [ ] Train security team on interpreting alerts

---

## Documentation

- [docs/QUICK_START.md](docs/QUICK_START.md) - 5-minute deployment
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design details
- [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) - Authentication layer setup (NGINX, Kong, AWS, Azure, mTLS)
- [docs/ALERTING_GUIDE.md](docs/ALERTING_GUIDE.md) - Prometheus alerts configuration
- [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) - Security incident response playbook
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) - Performance benchmark suite
- [docs/BACKUP_RECOVERY.md](docs/BACKUP_RECOVERY.md) - Backup and disaster recovery procedures
- [docs/MIGRATION_GUIDE.md](docs/MIGRATION_GUIDE.md) - Migrating from other security tools
- [docs/ARCHITECTURAL_LIMITATIONS.md](docs/ARCHITECTURAL_LIMITATIONS.md) - Detailed constraints
- [docs/DEPLOYMENT_GUIDES.md](docs/DEPLOYMENT_GUIDES.md) - Enterprise deployment scenarios

---

## License

MIT License

---

## Built With

- Rust 1.70+ (memory safety, performance)
- Tokio (async runtime)
- Axum (HTTP framework)
- Redis (session correlation)
- Prometheus + Grafana (monitoring)
- Docker (deployment)
