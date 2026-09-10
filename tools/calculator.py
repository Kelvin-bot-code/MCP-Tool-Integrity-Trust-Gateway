"""
MCP Tool: Calculator
Performs mathematical and arithmetic calculations with safety checks.
"""
import math
import re
from typing import Any, Dict
from tools.base import MCPToolDefinition, MCPToolResult

TOOL_DEFINITION = MCPToolDefinition(
    name="calculator",
    description="Performs mathematical calculations safely for arithmetic, powers, and scientific operations.",
    parameters={
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "Mathematical expression to compute, e.g. '(145 * 24) + 89' or 'sqrt(144) * 5'"
            }
        },
        "required": ["expression"]
    },
    version="1.0.0"
)

# Safe math environment
SAFE_GLOBALS = {
    "__builtins__": None,
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "pow": math.pow,
    "log": math.log,
    "pi": math.pi,
    "e": math.e,
    "abs": abs,
    "round": round
}

def execute(expression: str) -> Dict[str, Any]:
    """Execute arithmetic calculation safely."""
    # Sanitize expression: only allow math characters and safe functions
    clean_expr = expression.strip()
    if not re.match(r"^[0-9\+\-\*\/\(\)\.\,\s\%eEa-zA-Z_]+$", clean_expr):
        return {
            "status": "error",
            "message": "Invalid characters detected in math expression."
        }
    
    try:
        # Evaluate safely with restricted globals
        result = eval(clean_expr, SAFE_GLOBALS, {})
        return {
            "status": "success",
            "expression": clean_expr,
            "result": result
        }
    except Exception as exc:
        return {
            "status": "error",
            "expression": clean_expr,
            "message": f"Calculation error: {str(exc)}"
        } 