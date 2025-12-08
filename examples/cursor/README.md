# Cursor IDE Integration with Proxilion

This guide explains how to integrate Proxilion MCP Security Gateway with Cursor IDE.

---

## Overview

Cursor uses MCP (Model Context Protocol) to execute tool calls like bash commands and file operations. Proxilion intercepts these tool calls, analyzes them for threats, and blocks malicious operations.

**Important Limitation:** Cursor does not currently support custom MCP middleware or proxy configuration out of the box. This integration requires one of the following approaches:

1. **Network-level proxy** - Route all MCP traffic through Proxilion at the network layer
2. **Custom MCP server wrapper** - Wrap your MCP servers with Proxilion analysis
3. **Wait for Cursor to add proxy support** - Feature request pending

---

## Option 1: Network-Level Proxy (Recommended)

Route Cursor's MCP traffic through Proxilion using a transparent proxy.

### Architecture

```
Cursor IDE
    |
    v (MCP calls to localhost:3000)
iptables/socat redirect
    |
    v
Proxilion Gateway (:8787)
    |
    v (if allowed)
Actual MCP Server (:3000)
```

### Setup

#### Step 1: Start Proxilion with upstream forwarding

```bash
# Configure Proxilion to forward allowed requests to actual MCP server
docker run -d \
  --name proxilion \
  -p 8787:8787 \
  -e MODE=block \
  -e SESSION_STORE=inmemory \
  -e UPSTREAM_MCP_URL=http://host.docker.internal:3000 \
  proxilion/gateway
```

**Note:** `UPSTREAM_MCP_URL` is the address of your actual MCP server.

#### Step 2: Redirect traffic (Linux)

```bash
# Redirect localhost:3000 to Proxilion:8787
sudo iptables -t nat -A OUTPUT -p tcp --dport 3000 -j REDIRECT --to-port 8787
```

#### Step 2: Redirect traffic (macOS)

```bash
# Create pf rule
echo "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 3000 -> 127.0.0.1 port 8787" | sudo pfctl -ef -
```

#### Step 3: Start Cursor normally

Cursor will connect to what it thinks is the MCP server on port 3000, but traffic is redirected to Proxilion.

### Cleanup

```bash
# Linux - remove iptables rule
sudo iptables -t nat -D OUTPUT -p tcp --dport 3000 -j REDIRECT --to-port 8787

# macOS - disable pf rule
sudo pfctl -d
```

---

## Option 2: Custom MCP Server Wrapper

Wrap your MCP server with Proxilion analysis before executing commands.

### Architecture

```
Cursor IDE
    |
    v (MCP calls)
Proxilion MCP Wrapper (:3000)
    |
    v (analyze with Proxilion)
Proxilion Gateway (:8787)
    |
    v (if allowed, execute)
Actual command execution
```

### Implementation

Create a custom MCP server that proxies through Proxilion:

**mcp-proxilion-wrapper.ts:**

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const PROXILION_URL = process.env.PROXILION_URL || 'http://localhost:8787';
const USER_ID = process.env.USER_ID || 'cursor-user@company.com';

interface ProxilionResponse {
  decision: 'Allow' | 'Alert' | 'Block' | 'Terminate';
  threat_score: number;
  patterns: string[];
}

async function analyzeWithProxilion(toolCall: any): Promise<ProxilionResponse> {
  const response = await fetch(`${PROXILION_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tool_call: toolCall,
      user_id: USER_ID,
      session_id: `cursor-${Date.now()}`,
    }),
  });

  if (response.status === 403) {
    const data = await response.json();
    throw new Error(`Blocked by Proxilion: ${data.patterns.join(', ')}`);
  }

  return response.json();
}

const server = new Server(
  { name: 'proxilion-cursor-wrapper', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

// Wrap bash tool
server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'bash') {
    const toolCall = {
      Bash: {
        command: args.command,
        args: [],
        env: {},
      },
    };

    // Analyze with Proxilion first
    const analysis = await analyzeWithProxilion(toolCall);

    if (analysis.decision === 'Block' || analysis.decision === 'Terminate') {
      return {
        content: [
          {
            type: 'text',
            text: `Command blocked by security policy.\nThreat score: ${analysis.threat_score}\nPatterns: ${analysis.patterns.join(', ')}`,
          },
        ],
        isError: true,
      };
    }

    // Execute if allowed
    try {
      const result = await execAsync(args.command);
      return {
        content: [{ type: 'text', text: result.stdout || result.stderr }],
      };
    } catch (error: any) {
      return {
        content: [{ type: 'text', text: error.message }],
        isError: true,
      };
    }
  }

  // Handle other tools...
  return { content: [{ type: 'text', text: 'Unknown tool' }], isError: true };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
```

**package.json:**

```json
{
  "name": "proxilion-cursor-wrapper",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0"
  }
}
```

### Configure Cursor

Update your Cursor MCP configuration to use the wrapper:

**~/.cursor/mcp.json:**

```json
{
  "mcpServers": {
    "proxilion-bash": {
      "command": "node",
      "args": ["/path/to/mcp-proxilion-wrapper.js"],
      "env": {
        "PROXILION_URL": "http://localhost:8787",
        "USER_ID": "your-email@company.com"
      }
    }
  }
}
```

---

## Option 3: Sidecar with socat (Simple)

Use socat to create a simple TCP proxy.

### Setup

```bash
# Terminal 1: Start Proxilion
docker compose up -d

# Terminal 2: Start socat proxy
# This listens on 3000 and forwards to Proxilion on 8787
socat TCP-LISTEN:3000,fork,reuseaddr TCP:localhost:8787
```

### Limitations

- socat does not modify requests (no user_id injection)
- Limited visibility into session context
- Suitable for basic testing only

---

## Testing the Integration

### Verify Proxilion is Running

```bash
curl http://localhost:8787/health
# Expected: {"status":"healthy"}
```

### Test Threat Detection

```bash
# This should be blocked (score ~85)
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {"Bash": {"command": "nmap -sV 10.0.0.0/24", "args": [], "env": {}}},
    "user_id": "test@company.com",
    "session_id": "test-123"
  }'
```

Expected response:
```json
{
  "decision": "Block",
  "threat_score": 85.0,
  "patterns": ["nmap reconnaissance tool detected", "Internal network scan"]
}
```

### Test Safe Commands

```bash
# This should be allowed (score ~10)
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {"Bash": {"command": "ls -la", "args": [], "env": {}}},
    "user_id": "test@company.com",
    "session_id": "test-123"
  }'
```

Expected response:
```json
{
  "decision": "Allow",
  "threat_score": 0.0,
  "patterns": []
}
```

---

## Troubleshooting

### Cursor Cannot Connect to MCP Server

1. Check that Proxilion is running:
   ```bash
   curl http://localhost:8787/health
   ```

2. Check port redirect is active:
   ```bash
   # Linux
   sudo iptables -t nat -L -n | grep 3000

   # macOS
   sudo pfctl -s nat
   ```

3. Check Proxilion logs:
   ```bash
   docker logs proxilion-gateway
   ```

### Commands Are Being Blocked Incorrectly

1. Check threat score and patterns in Proxilion logs
2. Review if the command matches a known threat pattern
3. Consider running in `monitor` mode first to establish baseline:
   ```bash
   docker run -e MODE=monitor ...
   ```

### High Latency

1. Check Proxilion response times:
   ```bash
   time curl -X POST http://localhost:8787/analyze -d '...'
   ```

2. If >100ms, check:
   - Redis connection (if using Redis session store)
   - Network latency between Cursor and Proxilion
   - Semantic analysis (disable if not needed)

### Session Tracking Not Working

For session-aware detection (kill chain tracking), ensure consistent `session_id`:

```typescript
// Generate stable session ID per Cursor window
const sessionId = `cursor-${process.env.USER}-${Date.now()}`;
```

---

## Limitations

1. **No native Cursor support**: Cursor does not have built-in MCP proxy configuration. These are workarounds.

2. **Network proxy has limitations**: The iptables/pf approach intercepts all traffic on the port, which may affect other applications.

3. **User identification**: Cursor does not pass user identity to MCP servers. You must configure `USER_ID` manually or use environment variables.

4. **Conversation context**: The MCP wrapper does not have access to Cursor's conversation history, limiting social engineering detection.

5. **Feature request pending**: We recommend requesting native proxy support from Cursor team.

---

## Next Steps

1. Start with Option 2 (MCP wrapper) for most control
2. Test in monitor mode for 1 week
3. Review alerts and adjust thresholds
4. Switch to block mode for production

---

## Support

- Proxilion Issues: https://github.com/clay-good/proxilion/issues
- Cursor Documentation: https://cursor.sh/docs
