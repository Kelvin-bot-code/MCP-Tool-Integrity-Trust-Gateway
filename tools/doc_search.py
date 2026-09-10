"""
MCP Tool: Doc Search
Real filesystem documentation search tool.
Indexes and retrieves content directly from files stored in the local documents repository.
"""
from pathlib import Path
from typing import Any, Dict, List
from tools.base import MCPToolDefinition

TOOL_DEFINITION = MCPToolDefinition(
    name="doc_search",
    description="Searches internal proprietary organization documents in data_docs/ (e.g. internal security policy, gateway architecture). Do NOT use for general definitions or standard public knowledge.",
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Specific internal file topic or company policy keyword to search for"
            }
        },
        "required": ["query"]
    },
    version="1.0.0"
)

DOCS_DIR = Path(__file__).parent.parent / "data_docs"

def execute(query: str) -> Dict[str, Any]:
    """
    Performs real full-text search across all actual document files in DOCS_DIR.
    """
    if not DOCS_DIR.exists():
        DOCS_DIR.mkdir(parents=True, exist_ok=True)

    query_terms = [t.lower().strip() for t in query.split() if len(t.strip()) > 1]
    if not query_terms:
        return {
            "status": "error",
            "message": "Query string must contain at least one valid search term."
        }

    matches: List[Dict[str, Any]] = []

    # Read actual files from disk
    for file_path in DOCS_DIR.glob("**/*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in [".md", ".txt", ".json", ".csv"]:
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            filename_lower = file_path.name.lower()
            content_lower = content.lower()

            # Check if any terms match filename or content
            matching_terms = [t for t in query_terms if t in filename_lower or t in content_lower]
            if matching_terms:
                # Extract relevant matching paragraphs or lines
                lines = content.splitlines()
                relevant_snippets = []
                for idx, line in enumerate(lines, 1):
                    if any(t in line.lower() for t in matching_terms):
                        # Capture small context window
                        start_idx = max(0, idx - 2)
                        end_idx = min(len(lines), idx + 2)
                        snippet = "\n".join(lines[start_idx:end_idx])
                        if snippet not in relevant_snippets:
                            relevant_snippets.append(snippet)
                        if len(relevant_snippets) >= 3:
                            break

                matches.append({
                    "filename": file_path.name,
                    "filepath": str(file_path.relative_to(DOCS_DIR.parent)),
                    "file_size_bytes": file_path.stat().st_size,
                    "matched_terms": matching_terms,
                    "content_preview": "\n---\n".join(relevant_snippets) if relevant_snippets else content[:400]
                })
        except Exception as e:
            continue

    if not matches:
        return {
            "status": "not_found",
            "query": query,
            "message": f"No files in '{DOCS_DIR.name}' matched query '{query}'.",
            "indexed_files": [f.name for f in DOCS_DIR.glob("*.*")]
        }

    return {
        "status": "success",
        "query": query,
        "match_count": len(matches),
        "results": matches
    }
