"""
FastAPI Server for Real-Time MCP Tool Integrity & Trust Verification ChatBot.
Production-grade security proxy, dynamic tool registration, and integrity console.
"""
from pathlib import Path
from typing import Dict, Any, Optional
import ast
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import requests

from security.integrity_engine import integrity_engine
from security.hijack_detector import hijack_detector
from security.output_sanitizer import output_sanitizer
from agent.ollama_agent import agent_instance
from tools import get_available_tool_names, get_tool_file_path

app = FastAPI(
    title="MCP Tool Integrity & Trust Verification Engine",
    description="Real-time cryptographic file pinning and trust proxy for the Model Context Protocol",
    version="1.0.0"
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Request Models
class ChatRequest(BaseModel):
    message: str
    model: Optional[str] = "qwen2.5-coder:7b-instruct-q4_K_M"

class ToolActionRequest(BaseModel):
    tool_name: str

class RegisterToolRequest(BaseModel):
    tool_name: str
    code_content: str
    approver: Optional[str] = "Security_Admin"

class SaveToolContentRequest(BaseModel):
    tool_name: str
    code_content: str

@app.get("/")
def read_root():
    """Serve the enterprise security dashboard."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return JSONResponse({"status": "Dashboard loading..."})
    return FileResponse(index_file)

@app.get("/api/models")
def get_models():
    """Retrieve available Ollama models."""
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
        if r.status_code == 200:
            data = r.json()
            models = [m.get("name") for m in data.get("models", [])]
            return {"models": models, "default": "qwen2.5-coder:7b-instruct-q4_K_M"}
    except Exception:
        pass
    return {"models": ["qwen2.5-coder:7b-instruct-q4_K_M", "llama3:latest", "qwen2.5-coder:3b-instruct"], "default": "qwen2.5-coder:7b-instruct-q4_K_M"}

@app.get("/api/tools")
def list_tools():
    """List all registered tools, live vs baseline hashes, and verification status."""
    # Ensure any new tools on disk are included
    agent_instance._bootstrap_tools()
    statuses = integrity_engine.get_all_tool_statuses()
    return {"tools": statuses}

@app.get("/api/tools/{tool_name}/content")
def get_tool_content(tool_name: str):
    """Retrieve live file source and approved snapshot content for inspection/editing."""
    path = get_tool_file_path(tool_name)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Tool file {tool_name}.py not found on disk.")
    
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        live_content = f.read()

    store = integrity_engine._load_store()
    snapshot = store.get(tool_name, {}).get("snapshot_content", live_content)
    verification = integrity_engine.verify_tool(tool_name)

    return {
        "tool_name": tool_name,
        "file_path": str(path),
        "live_content": live_content,
        "snapshot_content": snapshot,
        "verification": verification
    }

@app.post("/api/tools/save")
def save_tool_content(req: SaveToolContentRequest):
    """
    Saves edited source code directly to disk.
    Immediately reflects in live file hash.
    """
    path = get_tool_file_path(req.tool_name)
    try:
        # Validate Python syntax before saving
        ast.parse(req.code_content)
    except SyntaxError as syn_err:
        raise HTTPException(status_code=400, detail=f"Syntax Error in Python code: {str(syn_err)}")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(req.code_content)

    # Re-verify and return status
    verification = integrity_engine.verify_tool(req.tool_name)
    return {
        "success": True,
        "tool_name": req.tool_name,
        "verification": verification
    }

@app.post("/api/tools/register")
def register_new_tool(req: RegisterToolRequest):
    """
    Registers a brand new Python MCP tool:
    1. Validates Python syntax.
    2. Writes tool source to tools/<tool_name>.py.
    3. Computes entire-file byte-level SHA-256 hash.
    4. Pins baseline hash and snapshot in the cryptographic registry.
    """
    tool_name = req.tool_name.strip().lower().replace(" ", "_").replace(".py", "")
    if not tool_name:
        raise HTTPException(status_code=400, detail="Tool name cannot be empty.")

    try:
        # Validate Python syntax
        ast.parse(req.code_content)
    except SyntaxError as syn_err:
        raise HTTPException(status_code=400, detail=f"Python syntax error: {str(syn_err)}")

    path = get_tool_file_path(tool_name)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(req.code_content)

    # Pin baseline hash in integrity store
    record = integrity_engine.register_tool(tool_name, path, approver=req.approver or "Security_Admin")

    return {
        "success": True,
        "message": f"Tool '{tool_name}' successfully registered and cryptographically pinned.",
        "record": record
    }

@app.post("/api/chat")
def handle_chat(req: ChatRequest):
    """Process a user prompt through the MCP security proxy to Ollama."""
    result = agent_instance.process_message(req.message, selected_model=req.model)
    return result

@app.post("/api/tools/approve")
def approve_tool(req: ToolActionRequest):
    """Legitimately re-approves an updated tool, pinning its new SHA-256 hash."""
    try:
        updated_record = integrity_engine.reapprove_tool(req.tool_name)
        return {
            "success": True,
            "message": f"Tool '{req.tool_name}' successfully re-approved. Pinned new baseline hash.",
            "record": updated_record
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/tools/revert")
def revert_tool(req: ToolActionRequest):
    """Reverts a mutated tool on disk back to its approved snapshot."""
    try:
        res = integrity_engine.revert_tool(req.tool_name)
        return {
            "success": True,
            "message": f"Tool '{req.tool_name}' restored to approved baseline snapshot.",
            "verification": res
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    agent_instance._bootstrap_tools()
    uvicorn.run(app, host="127.0.0.1", port=8000)
