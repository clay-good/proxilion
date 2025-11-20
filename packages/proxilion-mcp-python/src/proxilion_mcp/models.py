"""
Data models for Proxilion MCP middleware
"""

from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field


class ConversationTurn(BaseModel):
    """Represents a single conversation turn"""
    user_message: str
    ai_response: str
    timestamp: int


class ProxilionConfig(BaseModel):
    """Configuration for Proxilion MCP Client"""
    proxilion_endpoint: str = Field(default="http://localhost:8787")
    user_id: str
    session_id: Optional[str] = None
    org_id: Optional[str] = None
    mode: Literal['monitor', 'alert', 'block', 'terminate'] = 'block'
    enable_conversation_tracking: bool = True
    max_conversation_history: int = 50


class AnalysisRequest(BaseModel):
    """Request to analyze a tool call"""
    tool_call: Any
    session_id: str
    user_id: str
    org_id: Optional[str] = None
    user_message: Optional[str] = None
    ai_response: Optional[str] = None


class AnalysisResult(BaseModel):
    """Result of threat analysis"""
    decision: Literal['Allow', 'Alert', 'Block', 'Terminate']
    threat_score: float
    patterns_detected: List[str]
    analyzer_scores: Dict[str, float]
    session_terminated: bool
