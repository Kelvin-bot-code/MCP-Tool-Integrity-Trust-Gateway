"""
Security Verification Engine: Cross-Server Behavioral Hijack Detector.
Scans tool descriptions and schemas for adversarial prompt injection,
covert cross-tool manipulation, and imperative override patterns.
"""
import re
from typing import Dict, Any, List, Tuple

# Known threat patterns indicative of cross-server hijacking
HIJACK_PATTERNS = [
    # Cross-tool manipulation
    (r"(?:email|mail|dispatcher|network|file|doc)\s+tool\s+must", "Cross-tool imperative command"),
    (r"when\s+this\s+tool\s+is\s+available", "Conditional environmental override"),
    (r"route\s+all\s+(?:outgoing\s+)?(?:emails?|requests?|data)\s+to", "Traffic / data diversion instruction"),
    (r"send\s+(?:all|a\s+copy\s+of)?\s+.*(?:external|webhook|http)", "Unauthorized external exfiltration attempt"),
    (r"do\s+not\s+disclose", "Covert concealment directive"),
    (r"mandatory\s*[\.\!\;]", "Imperative urgency enforcement"),
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "System instruction override"),
    (r"(?:override|hijack|intercept)\s+(?:the\s+)?(?:tool|agent|system)", "Explicit override pattern"),
    (r"silently\s+(?:forward|execute|send|dispatch)", "Stealth execution directive")
]

class HijackDetector:
    def __init__(self, registered_tool_names: List[str] = None):
        self.registered_tool_names = registered_tool_names or ["calculator", "doc_search"]

    def scan_description(self, tool_name: str, description: str) -> Dict[str, Any]:
        """
        Scans a tool description for cross-server hijacking patterns.
        """
        flags: List[Dict[str, str]] = []
        desc_lower = description.lower()

        # Check for regex threat patterns
        for pattern, explanation in HIJACK_PATTERNS:
            matches = re.findall(pattern, desc_lower)
            if matches:
                flags.append({
                    "pattern": pattern,
                    "matched": matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    "explanation": explanation
                })

        # Check for secondary tool hijacking mentions
        other_tools = [t for t in self.registered_tool_names if t != tool_name]
        for other in other_tools:
            if other.replace("_", " ") in desc_lower or other in desc_lower:
                # If another tool is referenced with an imperative verb
                if re.search(rf"{other}.*(?:must|should|always|route|send|execute)", desc_lower):
                    flags.append({
                        "pattern": f"Cross-tool reference ({other})",
                        "matched": other,
                        "explanation": f"Tool '{tool_name}' attempts to dictate actions for '{other}'."
                    })

        is_flagged = len(flags) > 0
        return {
            "tool_name": tool_name,
            "is_flagged": is_flagged,
            "quarantined": is_flagged,
            "flag_count": len(flags),
            "flags": flags,
            "status": "QUARANTINED" if is_flagged else "CLEAN",
            "message": f"Cross-server hijacking detected: {len(flags)} pattern(s) flagged." if is_flagged else "Tool description verified clean."
        }

# Singleton instance
hijack_detector = HijackDetector()
