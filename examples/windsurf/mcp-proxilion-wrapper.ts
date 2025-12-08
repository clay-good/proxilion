/**
 * Proxilion MCP Wrapper for Windsurf IDE
 *
 * This MCP server wraps tool execution with Proxilion threat analysis.
 * All tool calls are analyzed before execution, and blocked if threat score >= 70.
 *
 * Usage:
 *   PROXILION_URL=http://localhost:8787 USER_ID=you@company.com node mcp-proxilion-wrapper.js
 *
 * Configure in Windsurf's mcp.json
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
const USER_ID = process.env.USER_ID || `windsurf-${process.env.USER || 'unknown'}@local`;
const SESSION_ID = process.env.SESSION_ID || `windsurf-session-${Date.now()}`;
const MODE = process.env.PROXILION_MODE || 'block';

// Logging utility
function log(level: string, message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logLine = data
    ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
    : `[${timestamp}] [${level}] ${message}`;
  console.error(logLine);
}

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
  const startTime = Date.now();

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

    const latency = Date.now() - startTime;
    const data = await response.json();

    log('INFO', `Proxilion analysis completed`, {
      latency_ms: latency,
      decision: data.decision,
      threat_score: data.threat_score,
    });

    if (response.status === 403) {
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
    const latency = Date.now() - startTime;
    log('ERROR', `Proxilion unavailable`, {
      latency_ms: latency,
      error: error.message,
      mode: MODE,
    });

    // Fail behavior based on mode
    if (MODE === 'block' || MODE === 'terminate') {
      return {
        decision: 'Block',
        threat_score: 0,
        patterns: ['Proxilion unavailable - failing closed for security'],
        session_terminated: false,
        session_id: SESSION_ID,
      };
    }

    return {
      decision: 'Allow',
      threat_score: 0,
      patterns: ['Proxilion unavailable - failing open (monitor mode)'],
      session_terminated: false,
      session_id: SESSION_ID,
    };
  }
}

/**
 * Format blocked response for display in Windsurf
 */
function formatBlockedResponse(analysis: ProxilionResponse): string {
  const lines = [
    '',
    '========================================',
    '  SECURITY ALERT - Operation Blocked',
    '========================================',
    '',
    `  Decision:     ${analysis.decision}`,
    `  Threat Score: ${analysis.threat_score}/100`,
    '',
    '  Patterns Detected:',
  ];

  for (const pattern of analysis.patterns) {
    lines.push(`    - ${pattern}`);
  }

  lines.push('');
  lines.push('  This operation was blocked by Proxilion');
  lines.push('  security gateway to protect your system.');
  lines.push('');
  lines.push('  If this is a false positive, contact your');
  lines.push('  security team with the patterns above.');
  lines.push('');
  lines.push('========================================');
  lines.push('');

  return lines.join('\n');
}

// Create MCP server
const server = new Server(
  {
    name: 'proxilion-windsurf-wrapper',
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
        name: 'run_terminal_command',
        description: 'Execute a terminal command (protected by Proxilion security)',
        inputSchema: {
          type: 'object',
          properties: {
            command: {
              type: 'string',
              description: 'The command to execute in the terminal',
            },
            working_directory: {
              type: 'string',
              description: 'Working directory for command execution',
            },
          },
          required: ['command'],
        },
      },
      {
        name: 'read_file',
        description: 'Read the contents of a file (protected by Proxilion security)',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute or relative path to the file',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'write_file',
        description: 'Write content to a file (protected by Proxilion security)',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute or relative path to the file',
            },
            content: {
              type: 'string',
              description: 'Content to write to the file',
            },
          },
          required: ['path', 'content'],
        },
      },
      {
        name: 'list_directory',
        description: 'List contents of a directory (protected by Proxilion security)',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to the directory',
            },
          },
          required: ['path'],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  log('INFO', `Tool call received`, { tool: name, args });

  let toolCall: ToolCall;
  let executeFunc: () => Promise<string>;

  switch (name) {
    case 'run_terminal_command': {
      const command = args?.command as string;
      const workingDir = args?.working_directory as string | undefined;

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
          env: workingDir ? { PWD: workingDir } : {},
        },
      };

      executeFunc = async () => {
        const options: any = {
          timeout: 60000,
          maxBuffer: 10 * 1024 * 1024,
        };
        if (workingDir) {
          options.cwd = workingDir;
        }

        const result = await execAsync(command, options);
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

      // Convert to cat command for Proxilion analysis
      toolCall = {
        Bash: {
          command: `cat "${filePath}"`,
          args: [],
          env: {},
        },
      };

      executeFunc = async () => {
        const absolutePath = path.resolve(filePath);
        const content = await fs.readFile(absolutePath, 'utf-8');
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
        const absolutePath = path.resolve(filePath);
        await fs.mkdir(path.dirname(absolutePath), { recursive: true });
        await fs.writeFile(absolutePath, content, 'utf-8');
        return `Successfully wrote ${content.length} bytes to ${filePath}`;
      };
      break;
    }

    case 'list_directory': {
      const dirPath = args?.path as string;
      if (!dirPath) {
        return {
          content: [{ type: 'text', text: 'Error: path is required' }],
          isError: true,
        };
      }

      toolCall = {
        Bash: {
          command: `ls -la "${dirPath}"`,
          args: [],
          env: {},
        },
      };

      executeFunc = async () => {
        const absolutePath = path.resolve(dirPath);
        const entries = await fs.readdir(absolutePath, { withFileTypes: true });

        const formatted = entries.map((entry) => {
          const type = entry.isDirectory() ? 'd' : entry.isSymbolicLink() ? 'l' : '-';
          return `${type} ${entry.name}`;
        });

        return formatted.join('\n');
      };
      break;
    }

    default:
      log('WARN', `Unknown tool requested`, { tool: name });
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }

  // Analyze with Proxilion
  const analysis = await analyzeWithProxilion(toolCall);

  // Handle blocked/terminated decisions
  if (analysis.decision === 'Block' || analysis.decision === 'Terminate') {
    log('WARN', `Tool call blocked`, {
      tool: name,
      decision: analysis.decision,
      threat_score: analysis.threat_score,
      patterns: analysis.patterns,
    });

    return {
      content: [{ type: 'text', text: formatBlockedResponse(analysis) }],
      isError: true,
    };
  }

  // Execute if allowed
  try {
    const result = await executeFunc();
    log('INFO', `Tool call executed successfully`, { tool: name });
    return {
      content: [{ type: 'text', text: result }],
    };
  } catch (error: any) {
    log('ERROR', `Tool execution failed`, { tool: name, error: error.message });
    return {
      content: [{ type: 'text', text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  log('INFO', 'Starting Proxilion MCP wrapper for Windsurf');
  log('INFO', `Configuration`, {
    proxilion_url: PROXILION_URL,
    user_id: USER_ID,
    session_id: SESSION_ID,
    mode: MODE,
  });

  // Health check Proxilion
  try {
    const health = await fetch(`${PROXILION_URL}/health`);
    if (health.ok) {
      log('INFO', 'Proxilion gateway is healthy');
    } else {
      log('WARN', 'Proxilion gateway health check failed', { status: health.status });
    }
  } catch (error: any) {
    log('WARN', 'Could not connect to Proxilion gateway', { error: error.message });
    if (MODE === 'block' || MODE === 'terminate') {
      log('WARN', 'Running in fail-closed mode - all commands will be blocked');
    }
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  log('INFO', 'MCP wrapper ready and listening');
}

main().catch((error) => {
  log('ERROR', `Fatal error`, { error: error.message, stack: error.stack });
  process.exit(1);
});
