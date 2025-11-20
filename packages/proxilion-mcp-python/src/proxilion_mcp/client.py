"""
Proxilion MCP Client implementation
"""

import time
import random
import string
from typing import Any, Callable, TypeVar, List
import httpx

from .models import (
    ConversationTurn,
    ProxilionConfig,
    AnalysisRequest,
    AnalysisResult,
)

T = TypeVar('T')


class ProxilionBlockedError(Exception):
    """Raised when Proxilion blocks a tool call"""
    
    def __init__(self, threat_score: float, patterns: List[str], decision: str):
        self.threat_score = threat_score
        self.patterns = patterns
        self.decision = decision
        super().__init__(
            f"Proxilion blocked this operation (score: {threat_score}, decision: {decision})"
        )


class ProxilionMCPClient:
    """
    Proxilion MCP middleware client for Python
    
    Wraps MCP tool calls with real-time threat analysis.
    """
    
    def __init__(self, config: ProxilionConfig):
        self.proxilion_endpoint = config.proxilion_endpoint
        self.user_id = config.user_id
        self.session_id = config.session_id or self._generate_session_id()
        self.org_id = config.org_id
        self.mode = config.mode
        self.enable_conversation_tracking = config.enable_conversation_tracking
        self.max_conversation_history = config.max_conversation_history
        
        self.conversation_history: List[ConversationTurn] = []
        self.http_client = httpx.AsyncClient()
    
    def _generate_session_id(self) -> str:
        """Generate a random session ID"""
        timestamp = int(time.time() * 1000)
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=13))
        return f"session_{timestamp}_{random_suffix}"
    
    def add_conversation_turn(self, user_message: str, ai_response: str) -> None:
        """Track a conversation turn for social engineering detection"""
        if not self.enable_conversation_tracking:
            return
        
        turn = ConversationTurn(
            user_message=user_message,
            ai_response=ai_response,
            timestamp=int(time.time() * 1000)
        )
        self.conversation_history.append(turn)
        
        # Keep only recent conversation history
        if len(self.conversation_history) > self.max_conversation_history:
            self.conversation_history.pop(0)
    
    async def call_tool_with_analysis(
        self,
        tool_call: Any,
        execute_tool_function: Callable[[Any], T]
    ) -> T:
        """
        Execute a tool call with Proxilion security analysis
        
        Args:
            tool_call: The MCP tool call to execute
            execute_tool_function: Function that executes the tool call
            
        Returns:
            The result of executing the tool call
            
        Raises:
            ProxilionBlockedError: If Proxilion blocks the operation
        """
        # Build analysis request
        request = AnalysisRequest(
            tool_call=tool_call,
            session_id=self.session_id,
            user_id=self.user_id,
            org_id=self.org_id,
        )
        
        # Add conversation context if tracking is enabled
        if self.enable_conversation_tracking and self.conversation_history:
            last_turn = self.conversation_history[-1]
            request.user_message = last_turn.user_message
            request.ai_response = last_turn.ai_response
        
        # Send to Proxilion for analysis
        analysis = await self._analyze_tool_call(request)
        
        # Handle decision
        if analysis.decision in ('Block', 'Terminate'):
            raise ProxilionBlockedError(
                analysis.threat_score,
                analysis.patterns_detected,
                analysis.decision
            )
        
        if analysis.decision == 'Alert':
            print(f"[Proxilion Alert] Threat score: {analysis.threat_score}")
            print(f"  Patterns: {analysis.patterns_detected}")
            print(f"  Session: {self.session_id}")
        
        # Execute the tool call if allowed
        return await execute_tool_function(tool_call)
    
    async def _analyze_tool_call(self, request: AnalysisRequest) -> AnalysisResult:
        """Analyze a tool call via Proxilion gateway"""
        try:
            response = await self.http_client.post(
                f"{self.proxilion_endpoint}/analyze",
                json=request.model_dump(exclude_none=True),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            
            return AnalysisResult(**response.json())
        
        except Exception as error:
            # If Proxilion is unavailable, decide based on mode
            if self.mode in ('monitor', 'alert'):
                print(f"[Proxilion] Gateway unavailable, allowing request: {error}")
                return AnalysisResult(
                    decision='Allow',
                    threat_score=0.0,
                    patterns_detected=[],
                    analyzer_scores={},
                    session_terminated=False
                )
            else:
                # In block/terminate mode, fail closed
                print(f"[Proxilion] Gateway unavailable, blocking request: {error}")
                raise ProxilionBlockedError(100.0, ['Gateway unavailable'], 'Block')
    
    def get_session_id(self) -> str:
        """Get the current session ID"""
        return self.session_id
    
    def reset_conversation(self) -> None:
        """Reset conversation history and generate new session ID"""
        self.conversation_history = []
        self.session_id = self._generate_session_id()
    
    async def close(self) -> None:
        """Close the HTTP client"""
        await self.http_client.aclose()


async def execute_bash_with_proxilion(
    command: str,
    client: ProxilionMCPClient,
    execute_function: Callable[[str], str]
) -> str:
    """
    Simple wrapper for bash commands with Proxilion analysis
    
    Args:
        command: Bash command to execute
        client: ProxilionMCPClient instance
        execute_function: Function that executes the bash command
        
    Returns:
        Command output
    """
    tool_call = {
        "Bash": {
            "command": command,
            "args": [],
            "env": {}
        }
    }
    
    return await client.call_tool_with_analysis(
        tool_call,
        lambda _: execute_function(command)
    )
