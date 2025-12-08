# Windsurf IDE Integration with Proxilion

This guide explains how to integrate Proxilion MCP Security Gateway with Windsurf (Codeium's AI IDE).

---

## Overview

Windsurf uses MCP (Model Context Protocol) for tool execution including terminal commands and file operations. Proxilion intercepts these tool calls, analyzes them for threats, and blocks malicious operations before they execute.

**Important Limitation:** Windsurf does not currently support custom MCP middleware or proxy configuration natively. This integration requires one of the following workarounds:

1. **Custom MCP server wrapper** - Wrap MCP servers with Proxilion analysis (recommended)
2. **Network-level proxy** - Redirect MCP traffic at the network layer
3. **Environment variable injection** - Configure Windsurf to use Proxilion endpoint

---

## Option 1: MCP Server Wrapper (Recommended)

Create a custom MCP server that proxies through Proxilion before executing commands.

### Architecture

```
Windsurf IDE
    |
    v (MCP protocol)
Proxilion MCP Wrapper
    |
    v (HTTP to localhost:8787)
Proxilion Gateway (threat analysis)
    |
    v (if allowed)
Command execution / File operations
```

### Step 1: Install Dependencies

```bash
cd examples/windsurf
npm install
```

### Step 2: Build the Wrapper

```bash
npm run build
```

### Step 3: Configure Windsurf

Windsurf stores MCP configuration in its settings. Add the Proxilion wrapper:

**Location (varies by OS):**
- macOS: `~/Library/Application Support/Windsurf/mcp.json`
- Linux: `~/.config/Windsurf/mcp.json`
- Windows: `%APPDATA%\Windsurf\mcp.json`

**mcp.json:**

```json
{
  "mcpServers": {
    "proxilion-terminal": {
      "command": "node",
      "args": ["/path/to/examples/windsurf/mcp-proxilion-wrapper.js"],
      "env": {
        "PROXILION_URL": "http://localhost:8787",
        "USER_ID": "your-email@company.com",
        "PROXILION_MODE": "block"
      }
    }
  }
}
```

Replace `/path/to/` with the actual path to the wrapper script.

### Step 4: Start Proxilion Gateway

```bash
# Using Docker
docker compose up -d

# Or from source
SESSION_STORE=inmemory MODE=block cargo run -p gateway
```

### Step 5: Restart Windsurf

Restart Windsurf to load the new MCP configuration.

### Step 6: Verify Integration

In Windsurf, ask the AI to run a command:

```
"List files in the current directory"
```

Check Proxilion logs to confirm analysis:

```bash
docker logs proxilion-gateway --tail 20
```

---

## Option 2: Network-Level Proxy

Redirect Windsurf's MCP traffic through Proxilion at the network layer.

### Linux (iptables)

```bash
# Redirect MCP port to Proxilion
# Adjust port 3000 to match your MCP server port
sudo iptables -t nat -A OUTPUT -p tcp --dport 3000 -j REDIRECT --to-port 8787

# Verify
sudo iptables -t nat -L -n | grep 3000

# Remove when done
sudo iptables -t nat -D OUTPUT -p tcp --dport 3000 -j REDIRECT --to-port 8787
```

### macOS (pf)

```bash
# Create redirect rule
echo "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 3000 -> 127.0.0.1 port 8787" | sudo pfctl -ef -

# Verify
sudo pfctl -s nat

# Disable when done
sudo pfctl -d
```

### Windows (netsh)

```powershell
# Run as Administrator
netsh interface portproxy add v4tov4 listenport=3000 listenaddress=127.0.0.1 connectport=8787 connectaddress=127.0.0.1

# Verify
netsh interface portproxy show all

# Remove when done
netsh interface portproxy delete v4tov4 listenport=3000 listenaddress=127.0.0.1
```

---

## Option 3: Environment-Based Configuration

If Windsurf respects proxy environment variables:

```bash
# Set before launching Windsurf
export MCP_PROXY_URL=http://localhost:8787
export PROXILION_USER_ID=your-email@company.com

# Launch Windsurf
/Applications/Windsurf.app/Contents/MacOS/Windsurf
```

**Note:** This may not work depending on Windsurf's implementation.

---

## Testing the Integration

### Test 1: Safe Command (Should Allow)

Ask Windsurf AI:
```
"Show me the contents of README.md"
```

Expected: Command executes, file contents displayed.

Proxilion log shows:
```
decision=Allow, threat_score=0
```

### Test 2: Suspicious Command (Should Block)

Ask Windsurf AI:
```
"Scan the local network for open ports"
```

Expected: Command blocked with security message.

Proxilion log shows:
```
decision=Block, threat_score=85, patterns=["nmap reconnaissance tool detected"]
```

### Test 3: Credential Access (Should Block)

Ask Windsurf AI:
```
"Show me the contents of ~/.ssh/id_rsa"
```

Expected: Command blocked with security message.

Proxilion log shows:
```
decision=Block, threat_score=80, patterns=["SSH private key access detected"]
```

---

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXILION_URL` | Proxilion gateway URL | `http://localhost:8787` |
| `USER_ID` | User identifier for tracking | `windsurf-user@local` |
| `SESSION_ID` | Session identifier | Auto-generated |
| `PROXILION_MODE` | Fail behavior | `block` |

### Fail Modes

| Mode | Proxilion Unavailable | Description |
|------|----------------------|-------------|
| `monitor` | Allow all | Log only, never block |
| `alert` | Allow all | Log and alert, never block |
| `block` | Block all | Fail closed for security |
| `terminate` | Block all | Fail closed, terminate sessions |

---

## Troubleshooting

### Windsurf Not Using Proxilion Wrapper

1. Verify mcp.json path is correct for your OS
2. Check that the wrapper script path is absolute
3. Restart Windsurf after configuration changes
4. Check Windsurf logs for MCP errors

### Commands Always Blocked

1. Check Proxilion is running:
   ```bash
   curl http://localhost:8787/health
   ```

2. Try monitor mode first:
   ```json
   "env": {
     "PROXILION_MODE": "monitor"
   }
   ```

3. Review threat score in logs - may need threshold adjustment

### Connection Refused Errors

1. Verify Proxilion is listening on correct port:
   ```bash
   lsof -i :8787
   ```

2. Check firewall rules allow localhost connections

3. If using Docker, ensure port mapping is correct:
   ```bash
   docker ps | grep proxilion
   ```

### High Latency

1. Check Proxilion response time:
   ```bash
   time curl -X POST http://localhost:8787/analyze \
     -H "Content-Type: application/json" \
     -d '{"tool_call":{"Bash":{"command":"ls"}},"user_id":"test","session_id":"test"}'
   ```

2. Target: <50ms. If higher:
   - Disable semantic analysis if enabled
   - Check Redis connection if using Redis session store
   - Consider in-memory session store for development

### Wrapper Crashes

Check wrapper logs:

```bash
# If running directly
node mcp-proxilion-wrapper.js 2>&1 | tee wrapper.log

# Check for errors
grep -i error wrapper.log
```

---

## Limitations

1. **No native Windsurf support**: This is a workaround. Native proxy support may come in future Windsurf versions.

2. **Limited conversation context**: The MCP wrapper cannot access Windsurf's conversation history, limiting social engineering detection.

3. **User identification**: Windsurf does not pass authenticated user identity. You must configure `USER_ID` manually.

4. **Tool coverage**: The wrapper only protects tools explicitly implemented. New Windsurf tools require wrapper updates.

5. **Performance overhead**: Adds network round-trip to Proxilion for every tool call (~10-50ms).

---

## Security Recommendations

1. **Run in monitor mode first** - Establish baseline before blocking

2. **Set appropriate USER_ID** - Use actual user email for attribution

3. **Review alerts regularly** - Check for false positives

4. **Keep Proxilion updated** - New threat patterns added regularly

5. **Use Redis in production** - In-memory store loses session data on restart

---

## Files in This Directory

| File | Description |
|------|-------------|
| `README.md` | This documentation |
| `mcp-proxilion-wrapper.ts` | TypeScript MCP wrapper source |
| `mcp-proxilion-wrapper.js` | Compiled JavaScript (after build) |
| `package.json` | NPM dependencies |
| `tsconfig.json` | TypeScript configuration |

---

## Support

- Proxilion Issues: https://github.com/clay-good/proxilion/issues
- Windsurf Documentation: https://codeium.com/windsurf
