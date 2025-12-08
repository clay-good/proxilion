/**
 * Proxilion MCP Wrapper for Cursor IDE
 *
 * This MCP server wraps tool execution with Proxilion threat analysis.
 * All tool calls are analyzed before execution, and blocked if threat score >= 70.
 *
 * Usage:
 *   PROXILION_URL=http://localhost:8787 USER_ID=you@company.com node mcp-proxilion-wrapper.js
 *
 * Configure in ~/.cursor/mcp.json
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execAsync = promisify(exec);

// Configuration
const PROXILION_URL = process.env.PROXILION_URL || 'http://localhost:8787';
const USER_ID = process.env.USER_ID || `cursor-${process.env.USER || 'unknown'}@local`;
const SESSION_ID = process.env.SESSION_ID || `cursor-session-${Date.now()}`;
const MODE = process.env.PROXILION_MODE || 'block'; // monitor, alert, block, terminate

interface ProxilionResponse {
  decision: 'Allow' | 'Alert' | 'Block' | 'Terminate';
  threat_score: number;
  patterns: string[];
  session_terminated: boolean;
  session_id: string;
}

interface ToolCall {
  Bash?: { command: string; args: string[]; env: Record<string, string> };
  FileSystem?: { operation: string; path: string; content?: string };
  Network?: { method: string; url: string; body?: string };
}

/**
 * Analyze a tool call with Proxilion before execution
 */
async function analyzeWithProxilion(toolCall: ToolCall): Promise<ProxilionResponse> {
  try {
    const response = await fetch(`${PROXILION_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_call: toolCall,
        user_id: USER_ID,
        session_id: SESSION_ID,
      }),
    });

    const data = await response.json();

    if (response.status === 403) {
      // Blocked or Terminated
      return {
        decision: data.session_terminated ? 'Terminate' : 'Block',
        threat_score: data.threat_score || 100,
        patterns: data.patterns || ['Request blocked'],
        session_terminated: data.session_terminated || false,
        session_id: SESSION_ID,
      };
    }

    return data as ProxilionResponse;
  } catch (error: any) {
    // If Proxilion is unavailable, fail open or closed based on config
    console.error(`Proxilion error: ${error.message}`);

    if (MODE === 'block' || MODE === 'terminate') {
      // Fail closed - block if we can't reach Proxilion
      return {
        decision: 'Block',
        threat_score: 0,
        patterns: ['Proxilion unavailable - failing closed'],
        session_terminated: false,
        session_id: SESSION_ID,
      };
    }

    // Fail open in monitor/alert mode
    return {
      decision: 'Allow',
      threat_score: 0,
      patterns: ['Proxilion unavailable - failing open'],
      session_terminated: false,
      session_id: SESSION_ID,
    };
  }
}

/**
 * Format blocked response for user
 */
function formatBlockedResponse(analysis: ProxilionResponse): string {
  return [
    '--- SECURITY ALERT ---',
    `Decision: ${analysis.decision}`,
    `Threat Score: ${analysis.threat_score}`,
    `Patterns Detected:`,
    ...analysis.patterns.map((p) => `  - ${p}`),
    '',
    'This operation was blocked by Proxilion security gateway.',
    'If you believe this is a false positive, contact your security team.',
    '----------------------',
  ].join('\n');
}

// Create MCP server
const server = new Server(
  {
    name: 'proxilion-cursor-wrapper',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'bash',
        description: 'Execute a bash command (protected by Proxilion)',
        inputSchema: {
          type: 'object',
          properties: {
            command: {
              type: 'string',
              description: 'The bash command to execute',
            },
          },
          required: ['command'],
        },
      },
      {
        name: 'read_file',
        description: 'Read contents of a file (protected by Proxilion)',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to the file to read',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'write_file',
        description: 'Write contents to a file (protected by Proxilion)',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to the file to write',
            },
            content: {
              type: 'string',
              description: 'Content to write to the file',
            },
          },
          required: ['path', 'content'],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  let toolCall: ToolCall;
  let executeFunc: () => Promise<string>;

  switch (name) {
    case 'bash': {
      const command = args?.command as string;
      if (!command) {
        return {
          content: [{ type: 'text', text: 'Error: command is required' }],
          isError: true,
        };
      }

      toolCall = {
        Bash: {
          command,
          args: [],
          env: {},
        },
      };

      executeFunc = async () => {
        const result = await execAsync(command, {
          timeout: 30000,
          maxBuffer: 10 * 1024 * 1024,
        });
        return result.stdout || result.stderr || 'Command completed with no output';
      };
      break;
    }

    case 'read_file': {
      const filePath = args?.path as string;
      if (!filePath) {
        return {
          content: [{ type: 'text', text: 'Error: path is required' }],
          isError: true,
        };
      }

      toolCall = {
        FileSystem: {
          operation: 'read',
          path: filePath,
        },
      };

      executeFunc = async () => {
        const content = await fs.readFile(filePath, 'utf-8');
        return content;
      };
      break;
    }

    case 'write_file': {
      const filePath = args?.path as string;
      const content = args?.content as string;
      if (!filePath || content === undefined) {
        return {
          content: [{ type: 'text', text: 'Error: path and content are required' }],
          isError: true,
        };
      }

      toolCall = {
        FileSystem: {
          operation: 'write',
          path: filePath,
          content,
        },
      };

      executeFunc = async () => {
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, content, 'utf-8');
        return `File written: ${filePath}`;
      };
      break;
    }

    default:
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }

  // Analyze with Proxilion
  const analysis = await analyzeWithProxilion(toolCall);

  // Log analysis result
  console.error(
    `[Proxilion] ${name}: score=${analysis.threat_score}, decision=${analysis.decision}`
  );

  // Check decision
  if (analysis.decision === 'Block' || analysis.decision === 'Terminate') {
    return {
      content: [{ type: 'text', text: formatBlockedResponse(analysis) }],
      isError: true,
    };
  }

  // Execute if allowed
  try {
    const result = await executeFunc();
    return {
      content: [{ type: 'text', text: result }],
    };
  } catch (error: any) {
    return {
      content: [{ type: 'text', text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[Proxilion] MCP wrapper started`);
  console.error(`[Proxilion] Gateway: ${PROXILION_URL}`);
  console.error(`[Proxilion] User: ${USER_ID}`);
  console.error(`[Proxilion] Session: ${SESSION_ID}`);
}

main().catch((error) => {
  console.error(`[Proxilion] Fatal error: ${error.message}`);
  process.exit(1);
});
