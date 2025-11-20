/**
 * Proxilion MCP Security Gateway Middleware
 *
 * Wraps MCP tool calls with real-time threat analysis.
 * Tracks conversation context for social engineering detection.
 */

export interface ConversationTurn {
  userMessage: string;
  aiResponse: string;
  timestamp: number;
}

export interface ProxilionConfig {
  proxilionEndpoint: string;
  userId: string;
  sessionId?: string;
  orgId?: string;
  mode: 'monitor' | 'alert' | 'block' | 'terminate';
  enableConversationTracking?: boolean;
  maxConversationHistory?: number;
}

export interface AnalysisRequest {
  tool_call: any;
  session_id: string;
  user_id: string;
  org_id?: string;
  user_message?: string;
  ai_response?: string;
}

export interface AnalysisResult {
  decision: 'Allow' | 'Alert' | 'Block' | 'Terminate';
  threat_score: number;
  patterns_detected: string[];
  analyzer_scores: Record<string, number>;
  session_terminated: boolean;
}

export class ProxilionBlockedError extends Error {
  constructor(
    public threatScore: number,
    public patterns: string[],
    public decision: string
  ) {
    super('Proxilion blocked this operation');
    this.name = 'ProxilionBlockedError';
  }
}

export class ProxilionMCPClient {
  private conversationHistory: ConversationTurn[] = [];
  private proxilionEndpoint: string;
  private userId: string;
  private sessionId: string;
  private orgId?: string;
  private mode: string;
  private enableConversationTracking: boolean;
  private maxConversationHistory: number;

  constructor(config: ProxilionConfig) {
    this.proxilionEndpoint = config.proxilionEndpoint || 'http://localhost:8787';
    this.userId = config.userId;
    this.sessionId = config.sessionId || this.generateSessionId();
    this.orgId = config.orgId;
    this.mode = config.mode;
    this.enableConversationTracking = config.enableConversationTracking ?? true;
    this.maxConversationHistory = config.maxConversationHistory ?? 50;
  }

  public addConversationTurn(userMessage: string, aiResponse: string): void {
    if (!this.enableConversationTracking) {
      return;
    }

    this.conversationHistory.push({
      userMessage,
      aiResponse,
      timestamp: Date.now(),
    });

    if (this.conversationHistory.length > this.maxConversationHistory) {
      this.conversationHistory.shift();
    }
  }

  public async callToolWithAnalysis<T>(
    toolCall: any,
    executeToolFunction: (toolCall: any) => Promise<T>
  ): Promise<T> {
    const analysisRequest: AnalysisRequest = {
      tool_call: toolCall,
      session_id: this.sessionId,
      user_id: this.userId,
      org_id: this.orgId,
    };

    if (this.enableConversationTracking && this.conversationHistory.length > 0) {
      const lastTurn = this.conversationHistory[this.conversationHistory.length - 1];
      analysisRequest.user_message = lastTurn.userMessage;
      analysisRequest.ai_response = lastTurn.aiResponse;
    }

    const analysis = await this.analyzeToolCall(analysisRequest);

    if (analysis.decision === 'Block' || analysis.decision === 'Terminate') {
      throw new ProxilionBlockedError(
        analysis.threat_score,
        analysis.patterns_detected,
        analysis.decision
      );
    }

    if (analysis.decision === 'Alert') {
      console.warn('[Proxilion Alert] Threat score: ' + analysis.threat_score, {
        patterns: analysis.patterns_detected,
        session_id: this.sessionId,
      });
    }

    return await executeToolFunction(toolCall);
  }

  private async analyzeToolCall(request: AnalysisRequest): Promise<AnalysisResult> {
    try {
      const response = await fetch(this.proxilionEndpoint + '/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error('Proxilion gateway error: ' + response.status);
      }

      return await response.json();
    } catch (error) {
      if (this.mode === 'monitor' || this.mode === 'alert') {
        console.error('[Proxilion] Gateway unavailable, allowing request:', error);
        return {
          decision: 'Allow',
          threat_score: 0,
          patterns_detected: [],
          analyzer_scores: {},
          session_terminated: false,
        };
      } else {
        console.error('[Proxilion] Gateway unavailable, blocking request:', error);
        throw new ProxilionBlockedError(100, ['Gateway unavailable'], 'Block');
      }
    }
  }

  private generateSessionId(): string {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
  }

  public getSessionId(): string {
    return this.sessionId;
  }

  public resetConversation(): void {
    this.conversationHistory = [];
    this.sessionId = this.generateSessionId();
  }
}

export async function executeBashWithProxilion(
  command: string,
  client: ProxilionMCPClient,
  executeFunction: (cmd: string) => Promise<string>
): Promise<string> {
  const toolCall = {
    Bash: {
      command,
      args: [],
      env: {},
    },
  };

  return await client.callToolWithAnalysis(toolCall, async () => {
    return await executeFunction(command);
  });
}
