"""
Ollama Agent Runtime with MCP Security Proxy & Cryptographic Integrity Verification.
Mediates all LLM tool interactions through:
1. Manifest Hijack Scanner
2. Entire-File Dynamic SHA-256 Hash Verification on Every Call
3. Tool Output Sanitizer
"""
import json
import time
import requests
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from tools import (
    get_available_tool_names,
    get_tool_file_path,
    load_tool_definition,
    execute_tool
)
from security.integrity_engine import integrity_engine
from security.hijack_detector import hijack_detector
from security.output_sanitizer import output_sanitizer

OLLAMA_BASE_URL = "http://127.0.0.1:11434"

class MCPSecurityAgent:
    def __init__(self, model_name: str = "qwen2.5-coder:7b-instruct-q4_K_M"):
        self.model_name = model_name
        self.conversation_history: List[Dict[str, Any]] = []
        self._bootstrap_tools()

    def _bootstrap_tools(self):
        """Initializes and pins baseline hashes for all available tools on disk."""
        for tool_name in get_available_tool_names():
            path = get_tool_file_path(tool_name)
            if path.exists():
                # Only register if not already pinned
                store = integrity_engine._load_store()
                if tool_name not in store:
                    integrity_engine.register_tool(tool_name, path)

    def get_registered_tools_schemas(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Loads tool schemas, scans descriptions through the Hijack Detector,
        and returns safe tool definitions formatted for Ollama.
        """
        safe_tools = []
        quarantined_tools = []

        for tool_name in get_available_tool_names():
            try:
                tool_def = load_tool_definition(tool_name)
                # Check for cross-server behavioral hijacking
                scan_res = hijack_detector.scan_description(tool_name, tool_def.description)
                
                if scan_res["quarantined"]:
                    quarantined_tools.append({
                        "tool_name": tool_name,
                        "reason": scan_res["flags"]
                    })
                    continue

                safe_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool_def.name,
                        "description": tool_def.description,
                        "parameters": tool_def.parameters
                    }
                })
            except Exception as e:
                pass

        return safe_tools, quarantined_tools

    def process_message(self, user_prompt: str, selected_model: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a real agent interaction with Ollama and the MCP Security Proxy.
        """
        model = selected_model or self.model_name
        
        # Build available tool list description for system context
        available_tools = get_available_tool_names()
        tools_str = ", ".join([f"'{t}'" for t in available_tools])
        
        system_instruction = (
            "You are an enterprise AI Assistant with access to internal MCP tools.\n\n"
            "CRITICAL TOOL INVOCATION RULES:\n"
            "- For general definitions, conceptual explanations, programming terms, greetings, or public knowledge (e.g. 'What is an API?', 'Explain REST', 'How does TCP work?'), answer directly using your own knowledge. DO NOT CALL ANY TOOLS.\n"
            "- ONLY invoke 'doc_search' when the user specifically asks to search internal private documentation, internal company guidelines, or organization policies.\n"
            "- ONLY invoke 'calculator' when the user asks to compute a specific numerical or arithmetic formula.\n"
            "Never call tools for general queries or standard terminology questions."
        )

        messages = [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_prompt}
        ]

        safe_tools, quarantined = self.get_registered_tools_schemas()
        
        audit_events = []
        
        if quarantined:
            for q in quarantined:
                audit_events.append({
                    "type": "HIJACK_QUARANTINE",
                    "level": "WARNING",
                    "tool": q["tool_name"],
                    "details": q["reason"],
                    "timestamp": time.time()
                })

        # Step 1: Query Ollama
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "keep_alive": -1
        }
        if safe_tools:
            payload["tools"] = safe_tools

        try:
            resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=300)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.HTTPError as exc:
            error_details = exc.response.text if exc.response else str(exc)
            
            # If the model doesn't support tools, retry without the tools array
            if exc.response and exc.response.status_code == 400 and "tools" in error_details.lower():
                payload.pop("tools", None)
                try:
                    resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=300)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as retry_exc:
                    return {
                        "success": False,
                        "error": f"Retry without tools failed: {str(retry_exc)}",
                        "audit_events": audit_events
                    }
            else:
                return {
                    "success": False,
                    "error": f"Failed to communicate with Ollama on {OLLAMA_BASE_URL}: {str(exc)} - Details: {error_details}",
                    "audit_events": audit_events
                }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Failed to communicate with Ollama on {OLLAMA_BASE_URL}: {str(exc)}",
                "audit_events": audit_events
            }

        response_msg = data.get("message", {})
        tool_calls = response_msg.get("tool_calls", [])

        # Fallback: Parse JSON tool invocation from message content if emitted inline
        if not tool_calls:
            content_str = response_msg.get("content", "").strip()
            if "```" in content_str:
                import re
                code_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content_str, re.DOTALL)
                if code_match:
                    content_str = code_match.group(1).strip()

            if content_str.startswith("{") and content_str.endswith("}"):
                try:
                    parsed_json = json.loads(content_str)
                    tool_candidate = parsed_json.get("name") or parsed_json.get("tool") or parsed_json.get("action")
                    if tool_candidate and tool_candidate in get_available_tool_names():
                        args = parsed_json.get("arguments") or parsed_json.get("parameters") or parsed_json.get("input") or {}
                        tool_calls = [{
                            "function": {
                                "name": tool_candidate,
                                "arguments": args
                            }
                        }]
                except Exception:
                    pass

        # Direct response without tool invocation
        if not tool_calls:
            return {
                "success": True,
                "response": response_msg.get("content", ""),
                "tool_calls": [],
                "audit_events": audit_events
            }

        # Step 2: Handle Tool Calls with Dynamic Entire-File Cryptographic Verification
        tool_call_results = []
        for call in tool_calls:
            func = call.get("function", {})
            tool_name = func.get("name")
            tool_args = func.get("arguments", {})

            if isinstance(tool_args, str):
                try:
                    tool_args = json.loads(tool_args)
                except Exception:
                    tool_args = {}

            # --- REAL CRYPTOGRAPHIC INTEGRITY CHECK ON EVERY CALL ---
            verification = integrity_engine.verify_tool(tool_name)
            
            audit_events.append({
                "type": "INTEGRITY_VERIFICATION",
                "level": "INFO" if verification["valid"] else "CRITICAL",
                "tool": tool_name,
                "live_hash": verification.get("live_hash"),
                "baseline_hash": verification.get("baseline_hash"),
                "status": verification["status"],
                "timestamp": time.time()
            })

            # If Hash Mismatch: HALT EXECUTION IMMEDIATELY
            if not verification["valid"]:
                audit_events.append({
                    "type": "EXECUTION_HALTED",
                    "level": "CRITICAL",
                    "tool": tool_name,
                    "reason": "Cryptographic file hash mismatch (Unauthorized mutation detected)",
                    "timestamp": time.time()
                })

                return {
                    "success": False,
                    "blocked_by_security": True,
                    "reason": "FILE_INTEGRITY_VIOLATION",
                    "tool_name": tool_name,
                    "verification": verification,
                    "response": (
                        f"**[SECURITY INCIDENT: EXECUTION SUSPENDED]**\n\n"
                        f"The tool **`{tool_name}`** failed cryptographic file integrity verification.\n"
                        f"- **Pinned Baseline Hash**: `{verification.get('baseline_hash')}`\n"
                        f"- **Live File Hash**: `{verification.get('live_hash')}`\n\n"
                        f"An unauthorized mutation or whitespace/code change was detected on disk in `{verification.get('file_path')}`. "
                        f"Execution was blocked prior to runtime. Review the diff and re-approve or revert in the console."
                    ),
                    "audit_events": audit_events
                }

            # Step 3: Verified Authentic -> Execute Live Tool on System
            start_t = time.time()
            try:
                raw_result = execute_tool(tool_name, **tool_args)
                exec_time = round((time.time() - start_t) * 1000, 2)
            except Exception as e:
                raw_result = {"error": f"Tool execution failed: {str(e)}"}
                exec_time = round((time.time() - start_t) * 1000, 2)

            # Step 4: Untrusted Output Sanitization (Indirect Prompt Injection Defense)
            sanitization = output_sanitizer.sanitize(raw_result)
            if sanitization["was_sanitized"]:
                audit_events.append({
                    "type": "OUTPUT_SANITIZED",
                    "level": "WARNING",
                    "tool": tool_name,
                    "threats": sanitization["threats"],
                    "timestamp": time.time()
                })

            sanitized_output = sanitization["sanitized"]
            tool_call_results.append({
                "tool_name": tool_name,
                "arguments": tool_args,
                "raw_result": raw_result,
                "sanitized_output": sanitized_output,
                "execution_time_ms": exec_time,
                "sanitized": sanitization["was_sanitized"],
                "threats": sanitization["threats"]
            })

            # Append tool messages for second LLM turn
            messages.append(response_msg)
            messages.append({
                "role": "tool",
                "content": json.dumps(sanitized_output),
                "name": tool_name
            })

        # Step 5: Second turn to let LLM formulate final answer from sanitized output
        synth_payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "keep_alive": -1
        }
        try:
            synth_resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=synth_payload, timeout=300)
            synth_resp.raise_for_status()
            final_data = synth_resp.json()
            final_content = final_data.get("message", {}).get("content", "")
        except Exception as e:
            final_content = f"Tool executed successfully. Verified Result: {json.dumps(tool_call_results[0]['sanitized_output'])}"

        return {
            "success": True,
            "response": final_content,
            "tool_calls": tool_call_results,
            "audit_events": audit_events
        }

agent_instance = MCPSecurityAgent()
