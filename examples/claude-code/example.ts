/**
 * Claude Code integration example with Proxilion security
 *
 * This shows how to integrate Proxilion with Claude Code (or any MCP client)
 * to add real-time threat detection.
 */

import { ProxilionMCPClient } from '@proxilion/mcp-middleware';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Initialize Proxilion client
const proxilion = new ProxilionMCPClient({
  proxilionEndpoint: 'http://localhost:8787',
  userId: 'developer@company.com',
  mode: 'block',
  enableConversationTracking: true,
});

// Example: Execute bash command with Proxilion protection
async function executeBashCommand(command: string): Promise<string> {
  const toolCall = {
    Bash: {
      command,
      args: [],
      env: {},
    },
  };

  try {
    const result = await proxilion.callToolWithAnalysis(toolCall, async () => {
      // Execute the actual command
      const output = await execAsync(command);
      return output.stdout || output.stderr;
    });

    return result;
  } catch (error: any) {
    if (error.name === 'ProxilionBlockedError') {
      console.error('Security Alert: Command blocked by Proxilion');
      console.error('Threat Score: ' + error.threatScore);
      console.error('Patterns: ' + error.patterns);
      throw new Error('Operation blocked by security policy');
    }
    throw error;
  }
}

// Example usage with conversation tracking
async function main() {
  // User asks AI to do something
  const userMessage = "Can you help me check what ports are open on the server?";
  const aiResponse = "I will scan the ports using nmap";

  // Track conversation for social engineering detection
  proxilion.addConversationTurn(userMessage, aiResponse);

  // AI tries to execute command
  try {
    const result = await executeBashCommand('nmap -sV localhost');
    console.log('Command executed:', result);
  } catch (error) {
    console.error('Command failed:', error);
  }
}

main();
