"""
Proxilion MCP Security Gateway Middleware for Python

Wraps MCP tool calls with real-time threat analysis.
"""

from .client import ProxilionMCPClient, ProxilionBlockedError, ConversationTurn
from .models import AnalysisRequest, AnalysisResult, ProxilionConfig

__all__ = [
    "ProxilionMCPClient",
    "ProxilionBlockedError",
    "ConversationTurn",
    "AnalysisRequest",
    "AnalysisResult",
    "ProxilionConfig",
]

__version__ = "0.1.0"
