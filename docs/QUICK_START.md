# Proxilion Quick Start Guide

Get Proxilion running in less than 5 minutes.

## Prerequisites

- Docker and Docker Compose (recommended)
- OR Rust 1.70+ (for building from source)
- 2GB RAM minimum
- Port 8787 available

## Option 1: Docker (Recommended)

### 1. Clone and Start

```bash
git clone https://github.com/clay-good/proxilion
cd proxilion
docker compose up -d
```

### 2. Verify Gateway is Running

```bash
curl http://localhost:8787/health
# Expected: {"status":"healthy"}
```

### 3. Test Threat Detection

```bash
./demo.sh
```

You should see:
- ✓ Safe commands allowed (ls -la)
- ✓ Network scanning blocked (nmap)
- ✓ Credential theft prevented (.env files)
- ✓ SSH key harvesting blocked (id_rsa)

### 4. Access Monitoring (Optional)

Start with Grafana dashboards:

```bash
docker compose --profile monitoring up -d
```

- **Grafana**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9090

## Option 2: Build from Source

### 1. Build

```bash
cargo build --release
```

### 2. Run

```bash
# Monitor mode (logs only, never blocks)
SESSION_STORE=inmemory MODE=monitor cargo run -p gateway

# Or use the release binary
./target/release/proxilion-gateway
```

### 3. Test

```bash
./demo.sh
```

## Configuration

Create a `.env` file:

```bash
# Operational mode
MODE=monitor  # monitor | alert | block | terminate

# Session storage
SESSION_STORE=inmemory  # inmemory | redis
REDIS_URL=redis://localhost:6379

# Semantic analysis (optional - requires Anthropic API key)
ENABLE_SEMANTIC_ANALYSIS=false
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Thresholds
ALERT_THRESHOLD=50
BLOCK_THRESHOLD=70
TERMINATE_THRESHOLD=90
```

## Modes Explained

### Monitor Mode (Safe for Production)
```bash
MODE=monitor docker compose up -d
```
- Analyzes all requests
- Logs threat scores
- **Never blocks** anything
- Perfect for baseline collection

### Alert Mode
```bash
MODE=alert docker compose up -d
```
- Analyzes and logs
- Sends alerts for scores >= 50
- Allows all execution
- Good for testing thresholds

### Block Mode (Recommended for Production)
```bash
MODE=block docker compose up -d
```
- Blocks requests with score >= 70
- Allows scores < 70
- Recommended for production deployments

### Terminate Mode (Highest Security)
```bash
MODE=terminate docker compose up -d
```
- Blocks requests with score >= 70
- **Terminates entire session** for score >= 90
- Use for high-security environments

## Integration with MCP Clients

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

# Track conversation
client.add_conversation_turn(user_message, ai_response)

# Execute with security analysis
result = await client.call_tool_with_analysis(tool_call, execute_func)
```

## API Usage

### Analyze a Tool Call

```bash
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {
      "Bash": {
        "command": "nmap -sV target.com",
        "args": [],
        "env": {}
      }
    },
    "user_id": "test_user",
    "session_id": "test_session"
  }'
```

Response:

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
    "enumeration": 75.0,
    "network_reconnaissance": 80.0
  },
  "session_terminated": false
}
```

## Common Use Cases

### For GitHub (Copilot Workspace)

Deploy as sidecar proxy to prevent:
- Source code exfiltration to external repos
- GitHub token/SSH key harvesting
- Internal network reconnaissance

```bash
MODE=block BLOCK_THRESHOLD=70 docker compose up -d
```

### For Anthropic (Enterprise Claude Code)

Enable semantic analysis for social engineering detection:

```bash
ENABLE_SEMANTIC_ANALYSIS=true \
ANTHROPIC_API_KEY=sk-ant-xxx \
MODE=block \
docker compose up -d
```

### For Startups (Cursor, Windsurf)

Start in monitor mode, collect baseline, then enable blocking:

```bash
# Week 1: Collect baseline
MODE=monitor docker compose up -d

# Week 2+: Enable blocking
MODE=block docker compose up -d
```

## Monitoring

View real-time metrics:

```bash
curl http://localhost:8787/metrics
```

Grafana dashboards (with `--profile monitoring`):
- **Overview**: Threat detection rates, latency, decisions
- **Analyzers**: Per-analyzer performance and scores
- **Costs**: Semantic analysis cost tracking with prompt caching

## Troubleshooting

### Gateway not responding

```bash
docker compose logs gateway
```

### High false positive rate

1. Run in monitor mode for 1 week
2. Collect baseline data
3. Adjust thresholds based on your environment

### Low detection rate

1. Enable semantic analysis (requires Anthropic API key)
2. Verify all 25 analyzers are active in logs
3. Check session state is properly tracked (use Redis, not inmemory)

## Production Checklist

Before deploying to production:

- [ ] Run in monitor mode for 1+ week
- [ ] Review false positive rate (target: <5%)
- [ ] Configure Redis for session persistence
- [ ] Set up Prometheus + Grafana monitoring
- [ ] Configure alerts for high threat scores
- [ ] Document incident response procedures
- [ ] Test fail-open vs fail-closed behavior
- [ ] Set appropriate thresholds for your environment

## Next Steps

- Read [DEPLOYMENT_GUIDES.md](DEPLOYMENT_GUIDES.md) for platform-specific instructions
- Review [ARCHITECTURE.md](ARCHITECTURE.md) to understand how it works
- Check [COST_OPTIMIZATION.md](COST_OPTIMIZATION.md) for semantic analysis cost reduction
- Join discussions at GitHub Issues

## Support

- **Issues**: https://github.com/clay-good/proxilion/issues
- **Discussions**: https://github.com/clay-good/proxilion/discussions
- **Security**: See [SECURITY.md](SECURITY.md)
