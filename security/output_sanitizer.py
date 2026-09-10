"""
Security Verification Engine: Tool Output Sanitizer (Indirect Prompt Injection Defense).
Treats all tool execution results as untrusted external data.
Detects, neutralizes, and strips embedded imperative instructions, adversarial prompt injections,
control tokens, and covert data exfiltration links before data re-enters the agent context.
"""
import re
from typing import Dict, Any, List, Union

# Robust, generic prompt injection and exfiltration detection patterns
UNTRUSTED_INJECTION_PATTERNS = [
    # Explicit Injection tags
    (r"\[INDIRECT_PROMPT_INJECTION:[^\]]*\]", "Adversarial Prompt Injection Tag"),
    # Instruction overrides & jailbreaks
    (r"(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|rules|prompts|guidelines)", "Instruction override / Jailbreak attempt"),
    
    # Embedded imperative trigger commands
    (r"(?:when|after)\s+(?:this\s+is\s+)?(?:retrieved|read|accessed|loaded|called)[,\s]+(?:you\s+must|please|create|summarize|send|exfiltrate|forward|dump)[^\.\n]*", "Embedded retrieval action trigger"),
    
    # Covert concealment instructions
    (r"(?:do\s+not|never)\s+(?:disclose|mention|reveal|inform|tell\s+the\s+user|alert)[^\.\n]*", "Covert concealment directive"),
    (r"mandatory\s*[\.\!\;]\s*(?:do\s+not\s+disclose)?", "Imperative secrecy directive"),
    
    # LLM Control tokens & chat template delimiters
    (r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[SYSTEM\]|\[AGENT\]|\[INST\]|\[\/INST\]|###\s*(?:System|Instruction|Assistant):", "Adversarial chat control token injection"),
    
    # Exfiltration webhooks and markdown image traps
    (r"\!\[.*?\]\((https?:\/\/[^\s\)\"\']+(?:\?[^\s\)\"\']*)?)\)", "Markdown image exfiltration trap"),
    (r"(?:exfiltrate|transmit|send\s+copy|leak)\s+(?:data|files|secrets|credentials|context)\s+to\s+(?:https?:\/\/[^\s\)\"\']+)", "Explicit data exfiltration directive"),
    (r"https?:\/\/(?:[a-zA-Z0-9_\-\.]+\.)?(?:webhook\.site|pipedream\.net|requestbin|ngrok-free\.app|attacker)[^\s\)\"\']*", "Suspicious exfiltration endpoint URL")
]

class OutputSanitizer:
    def sanitize(self, raw_output: Any) -> Dict[str, Any]:
        """
        Recursively scans and sanitizes tool execution outputs.
        Neutralizes detected imperative injection patterns.
        """
        if isinstance(raw_output, dict):
            sanitized_dict = {}
            threats: List[Dict[str, str]] = []
            for k, v in raw_output.items():
                sub_res = self.sanitize(v)
                sanitized_dict[k] = sub_res["sanitized"]
                threats.extend(sub_res.get("threats", []))
            return {
                "sanitized": sanitized_dict,
                "was_sanitized": len(threats) > 0,
                "threats": threats
            }
        elif isinstance(raw_output, list):
            sanitized_list = []
            threats: List[Dict[str, str]] = []
            for item in raw_output:
                sub_res = self.sanitize(item)
                sanitized_list.append(sub_res["sanitized"])
                threats.extend(sub_res.get("threats", []))
            return {
                "sanitized": sanitized_list,
                "was_sanitized": len(threats) > 0,
                "threats": threats
            }
        elif not isinstance(raw_output, str):
            return {
                "sanitized": raw_output,
                "was_sanitized": False,
                "threats": []
            }

        # Text analysis
        text = str(raw_output)
        clean_text = text
        threats_found: List[Dict[str, str]] = []

        for pattern, desc in UNTRUSTED_INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, clean_text, flags=re.IGNORECASE))
            for m in matches:
                matched_str = m.group(0)
                threats_found.append({
                    "type": desc,
                    "matched": matched_str
                })
                # Redact the adversarial instruction safely
                clean_text = clean_text.replace(
                    matched_str,
                    f"[SECURITY REDACTED: {desc}]"
                )

        return {
            "sanitized": clean_text,
            "was_sanitized": len(threats_found) > 0,
            "threats": threats_found
        }

# Singleton instance
output_sanitizer = OutputSanitizer()
