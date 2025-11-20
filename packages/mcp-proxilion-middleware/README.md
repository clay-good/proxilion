# Proxilion MCP Middleware (TypeScript)

TypeScript middleware for integrating Proxilion MCP Security Gateway with MCP clients.

## Installation

```bash
npm install @proxilion/mcp-middleware
```

## Usage

```typescript
import { ProxilionMCPClient } from '@proxilion/mcp-middleware';

// Create client
const client = new ProxilionMCPClient({
  proxilionEndpoint: 'http://localhost:8787',
  userId: 'user@company.com',
  mode: 'block',
  enableConversationTracking: true,
});

// Track conversation for social engineering detection
client.addConversationTurn(userMessage, aiResponse);

// Execute tools with security analysis
try {
  const result = await client.callToolWithAnalysis(
    { Bash: { command: 'ls -la', args: [], env: {} } },
    async (toolCall) => {
      // Your tool execution logic here
      return executeBashCommand(toolCall.Bash.command);
    }
  );
  console.log(result);
} catch (error) {
  if (error instanceof ProxilionBlockedError) {
    console.error('Blocked by Proxilion:', error.threatScore, error.patterns);
  }
}
```

## Configuration

| Option | Type | Description |
|--------|------|-------------|
| `proxilionEndpoint` | string | Proxilion gateway URL (default: http://localhost:8787) |
| `userId` | string | User identifier for analysis |
| `sessionId` | string | Session ID (auto-generated if not provided) |
| `orgId` | string | Organization ID (optional) |
| `mode` | string | 'monitor' \| 'alert' \| 'block' \| 'terminate' |
| `enableConversationTracking` | boolean | Enable social engineering detection (default: true) |
| `maxConversationHistory` | number | Max turns to track (default: 50) |

## License

MIT
