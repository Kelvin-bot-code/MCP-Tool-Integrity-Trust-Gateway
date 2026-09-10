"""
Security Verification Engine: Entire-File Cryptographic Integrity Verification.
Computes byte-level SHA-256 hashes across entire tool source files.
Even a single whitespace, comment, or character modification is instantly detected.
"""
import hashlib
import json
import difflib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

STORE_PATH = Path(__file__).parent / "integrity_store.json"

class IntegrityEngine:
    def __init__(self, store_path: Path = STORE_PATH):
        self.store_path = store_path
        self._ensure_store()

    def _ensure_store(self):
        """Initializes store file if missing."""
        if not self.store_path.exists():
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump({}, f, indent=2)

    def _load_store(self) -> Dict[str, Any]:
        """Loads store from disk."""
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_store(self, data: Dict[str, Any]):
        """Persists store to disk."""
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def compute_file_hash(filepath: Path) -> str:
        """
        Computes SHA-256 hash over the entire raw bytes of the file.
        Detects even a single whitespace or character difference.
        """
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        with open(filepath, "rb") as f:
            raw_bytes = f.read()
        return hashlib.sha256(raw_bytes).hexdigest()

    def register_tool(self, tool_name: str, file_path: Path, approver: str = "Security_Admin") -> Dict[str, Any]:
        """
        Registers a tool and pins its entire-file SHA-256 hash baseline along with snapshot.
        """
        file_path = file_path.resolve()
        current_hash = self.compute_file_hash(file_path)
        with open(file_path, "r", encoding="utf-8", newline="") as f:
            content = f.read()

        record = {
            "tool_name": tool_name,
            "file_path": str(file_path),
            "baseline_hash": current_hash,
            "approved_at": datetime.now().isoformat(),
            "approved_by": approver,
            "snapshot_content": content,
            "status": "VERIFIED"
        }

        store = self._load_store()
        store[tool_name] = record
        self._save_store(store)
        return record

    def verify_tool(self, tool_name: str, file_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Verifies the live tool file against the pinned cryptographic baseline hash.
        If any mutation or whitespace change is detected:
        Returns status 'MUTATION_DETECTED' and generates a line-by-line diff.
        """
        store = self._load_store()
        if tool_name not in store:
            # If not registered, register on first observation or flag
            if file_path and file_path.exists():
                return self.register_tool(tool_name, file_path)
            return {
                "valid": False,
                "tool_name": tool_name,
                "status": "UNREGISTERED",
                "message": f"Tool '{tool_name}' has not been cryptographically pinned."
            }

        record = store[tool_name]
        path = Path(record["file_path"])
        if not path.exists():
            return {
                "valid": False,
                "tool_name": tool_name,
                "status": "FILE_MISSING",
                "message": f"Source file for '{tool_name}' is missing at {path}."
            }

        live_hash = self.compute_file_hash(path)
        baseline_hash = record["baseline_hash"]

        with open(path, "r", encoding="utf-8") as f:
            live_content = f.read()

        diff_text = ""
        is_valid = (live_hash == baseline_hash)
        status = "VERIFIED" if is_valid else "MUTATION_DETECTED"

        if not is_valid:
            # Generate diff between approved snapshot and live file
            snapshot_lines = record.get("snapshot_content", "").splitlines(keepends=True)
            live_lines = live_content.splitlines(keepends=True)
            diff_generator = difflib.unified_diff(
                snapshot_lines,
                live_lines,
                fromfile=f"Approved Snapshot ({baseline_hash[:8]}...)",
                tofile=f"Live Modified File ({live_hash[:8]}...)",
                lineterm=""
            )
            diff_text = "\n".join(diff_generator)

        # Update record with latest evaluation for this tool
        record["live_hash"] = live_hash
        record["status"] = status
        record["diff"] = diff_text
        store[tool_name] = record
        self._save_store(store)

        if is_valid:
            return {
                "valid": True,
                "tool_name": tool_name,
                "live_hash": live_hash,
                "baseline_hash": baseline_hash,
                "status": "VERIFIED",
                "approved_at": record.get("approved_at"),
                "file_path": str(path),
                "message": "File integrity verified (Byte-for-byte SHA-256 match)."
            }
        else:
            return {
                "valid": False,
                "tool_name": tool_name,
                "live_hash": live_hash,
                "baseline_hash": baseline_hash,
                "status": "MUTATION_DETECTED",
                "diff": diff_text,
                "file_path": str(path),
                "approved_at": record.get("approved_at"),
                "message": f"CRITICAL INTEGRITY VIOLATION: Tool '{tool_name}' source file was altered! Hash mismatch detected."
            }

    def reapprove_tool(self, tool_name: str, approver: str = "Security_Admin") -> Dict[str, Any]:
        """
        Legitimate update re-approval: Updates the baseline hash and snapshot.
        """
        store = self._load_store()
        if tool_name not in store:
            raise ValueError(f"Tool {tool_name} not registered.")
        record = store[tool_name]
        path = Path(record["file_path"])
        return self.register_tool(tool_name, path, approver=approver)

    def revert_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Reverts the modified live file on disk back to the approved snapshot.
        """
        store = self._load_store()
        if tool_name not in store:
            raise ValueError(f"Tool {tool_name} not registered.")
        record = store[tool_name]
        path = Path(record["file_path"])
        snapshot = record.get("snapshot_content", "")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(snapshot)
        return self.verify_tool(tool_name)

    def get_all_tool_statuses(self) -> Dict[str, Any]:
        """
        Returns recorded statuses without re-evaluating every uncalled tool file on disk.
        Only the tool being invoked is evaluated dynamically.
        """
        store = self._load_store()
        results = {}
        for tool_name, record in store.items():
            results[tool_name] = {
                "valid": record.get("status", "VERIFIED") == "VERIFIED",
                "tool_name": tool_name,
                "live_hash": record.get("live_hash", record.get("baseline_hash")),
                "baseline_hash": record.get("baseline_hash"),
                "status": record.get("status", "VERIFIED"),
                "file_path": record.get("file_path"),
                "approved_at": record.get("approved_at"),
                "diff": record.get("diff", "")
            }
        return results

# Singleton instance
integrity_engine = IntegrityEngine()
