"""
Base interface and schemas for Python Model Context Protocol (MCP) Tools.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class MCPToolDefinition(BaseModel):
    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Human and LLM readable purpose of the tool")
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema formatted input parameters for the tool"
    )
    version: str = Field(default="1.0.0", description="Semantic tool version")

class MCPToolResult(BaseModel):
    tool_name: str
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time_ms: float = 0.0
