"""
Tools registry and loader for MCP tools.
Dynamically discovers and loads all valid Python MCP tools from disk.
"""
from typing import Dict, Any, List
import importlib
import sys
from pathlib import Path
from tools.base import MCPToolDefinition

TOOLS_DIR = Path(__file__).parent.resolve()

def get_available_tool_names() -> List[str]:
    """Dynamically finds all valid Python tool scripts in the tools directory."""
    tools = []
    for file_path in TOOLS_DIR.glob("*.py"):
        if file_path.name in ["__init__.py", "base.py"]:
            continue
        tools.append(file_path.stem)
    return sorted(tools)

def get_tool_file_path(tool_name: str) -> Path:
    """Returns absolute path to the tool's python source file."""
    return TOOLS_DIR / f"{tool_name}.py"

def load_tool_definition(tool_name: str) -> MCPToolDefinition:
    """Dynamically loads and returns the tool definition."""
    module_name = f"tools.{tool_name}"
    if module_name in sys.modules:
        module = importlib.reload(sys.modules[module_name])
    else:
        module = importlib.import_module(module_name)
        
    if not hasattr(module, "TOOL_DEFINITION"):
        raise AttributeError(f"Module {module_name} does not define 'TOOL_DEFINITION'")
    return getattr(module, "TOOL_DEFINITION")

def execute_tool(tool_name: str, **kwargs) -> Any:
    """Dynamically reloads and executes the tool with kwargs."""
    module_name = f"tools.{tool_name}"
    if module_name in sys.modules:
        module = importlib.reload(sys.modules[module_name])
    else:
        module = importlib.import_module(module_name)

    if not hasattr(module, "execute"):
        raise AttributeError(f"Module {module_name} does not define 'execute' function")
    execute_fn = getattr(module, "execute")
    return execute_fn(**kwargs)
