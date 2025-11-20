# Proxilion MCP Middleware (Python)

Python middleware for integrating Proxilion MCP Security Gateway with MCP clients.

## Installation

```bash
pip install proxilion-mcp
```

## Usage

```python
import asyncio
from proxilion_mcp import ProxilionMCPClient, ProxilionConfig, ProxilionBlockedError

# Create client
client = ProxilionMCPClient(ProxilionConfig(
    proxilion_endpoint="http://localhost:8787",
    user_id="user@company.com",
    mode="block",
    enable_conversation_tracking=True,
))

# Track conversation for social engineering detection
client.add_conversation_turn(user_message, ai_response)

# Execute tools with security analysis
async def execute_tool(tool_call):
    # Your tool execution logic here
    return execute_bash_command(tool_call["Bash"]["command"])

try:
    result = await client.call_tool_with_analysis(
        {"Bash": {"command": "ls -la", "args": [], "env": {}}},
        execute_tool
    )
    print(result)
except ProxilionBlockedError as e:
    print(f"Blocked: score={e.threat_score}, patterns={e.patterns}")
finally:
    await client.close()
```

## Configuration

| Option | Type | Description |
|--------|------|-------------|
| `proxilion_endpoint` | str | Proxilion gateway URL (default: http://localhost:8787) |
| `user_id` | str | User identifier for analysis |
| `session_id` | str | Session ID (auto-generated if not provided) |
| `org_id` | str | Organization ID (optional) |
| `mode` | str | 'monitor' \| 'alert' \| 'block' \| 'terminate' |
| `enable_conversation_tracking` | bool | Enable social engineering detection (default: True) |
| `max_conversation_history` | int | Max turns to track (default: 50) |

## License

MIT
