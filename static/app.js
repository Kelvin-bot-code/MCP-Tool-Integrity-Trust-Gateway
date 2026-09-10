/**
 * MCP Tool Integrity & Trust Verification Console
 * Production JavaScript Controller
 * 
 * Features:
 * - Real-time targeted SHA-256 integrity verification
 * - Zero raw data dumps: all technical I/O & hashes accessible via interactive popup buttons
 * - Industrial Orange (80%) and Security Red (20%) theme integration
 */

let activeTools = {};
let currentActiveTool = "calculator";
window._telemetryHistory = {};
window._currentHashTool = null;

// DOM Elements: Core
const chatStream = document.getElementById("chat-stream");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSubmit = document.getElementById("btn-submit");
const btnClearChat = document.getElementById("btn-clear-chat");
const modelSelector = document.getElementById("model-selector");
const toolsInventory = document.getElementById("tools-inventory");

// Modal 1: Unified Diff
const diffModal = document.getElementById("diff-modal");
const btnCloseDiffModal = document.getElementById("btn-close-diff-modal");
const diffBaselineHash = document.getElementById("diff-baseline-hash");
const diffLiveHash = document.getElementById("diff-live-hash");
const diffPreElement = document.getElementById("diff-pre-element");
const diffFileTarget = document.getElementById("diff-file-target");
const btnActionApprove = document.getElementById("btn-action-approve");
const btnActionRevert = document.getElementById("btn-action-revert");

// Modal 2: Source Code Editor
const editorModal = document.getElementById("editor-modal");
const btnCloseEditorModal = document.getElementById("btn-close-editor-modal");
const editorFilePath = document.getElementById("editor-file-path");
const editorLiveStatusPill = document.getElementById("editor-live-status-pill");
const editorTextarea = document.getElementById("editor-textarea");
const btnEditorSave = document.getElementById("btn-editor-save");
const btnEditorCancel = document.getElementById("btn-editor-cancel");

// Modal 3: Register Tool
const registerModal = document.getElementById("register-modal");
const btnOpenRegisterModal = document.getElementById("btn-open-register-modal");
const btnCloseRegisterModal = document.getElementById("btn-close-register-modal");
const newToolNameInput = document.getElementById("new-tool-name");
const newToolCodeTextarea = document.getElementById("new-tool-code");
const btnRegisterSubmit = document.getElementById("btn-register-submit");
const btnRegisterCancel = document.getElementById("btn-register-cancel");

// Modal 4: Tool Execution Telemetry & Security Proof
const telemetryModal = document.getElementById("telemetry-modal");
const btnCloseTelemetryModal = document.getElementById("btn-close-telemetry-modal");
const btnCloseTelemetryModalBottom = document.getElementById("btn-close-telemetry-modal-bottom");
const telemetryModalStatusBadge = document.getElementById("telemetry-modal-status-badge");
const telemetryModalTitle = document.getElementById("telemetry-modal-title");
const telemetryModalToolName = document.getElementById("telemetry-modal-tool-name");
const telemetryModalLatency = document.getElementById("telemetry-modal-latency");
const telemetryModalArguments = document.getElementById("telemetry-modal-arguments");
const telemetryModalOutput = document.getElementById("telemetry-modal-output");
const telemetryModalProof = document.getElementById("telemetry-modal-proof");

// Modal 5: Cryptographic Hash Fingerprint
const hashModal = document.getElementById("hash-modal");
const btnCloseHashModal = document.getElementById("btn-close-hash-modal");
const btnCloseHashModalBottom = document.getElementById("btn-close-hash-modal-bottom");
const btnHashModalEdit = document.getElementById("btn-hash-modal-edit");
const hashModalStatusBadge = document.getElementById("hash-modal-status-badge");
const hashModalFilePath = document.getElementById("hash-modal-file-path");
const hashModalBaselineVal = document.getElementById("hash-modal-baseline-val");
const hashModalLiveVal = document.getElementById("hash-modal-live-val");
const hashModalStatusDesc = document.getElementById("hash-modal-status-desc");

// Init
document.addEventListener("DOMContentLoaded", () => {
  fetchModels();
  fetchTools();
  attachEventHandlers();
});

function attachEventHandlers() {
  chatForm.addEventListener("submit", handleChatSubmit);
  btnClearChat.addEventListener("click", () => {
    chatStream.innerHTML = "";
    appendAudit("Chat session cleared by operator.", "info");
  });

  // Modal Closures: Diff
  btnCloseDiffModal.addEventListener("click", () => diffModal.classList.add("hidden"));

  // Modal Closures: Editor
  btnCloseEditorModal.addEventListener("click", () => editorModal.classList.add("hidden"));
  btnEditorCancel.addEventListener("click", () => editorModal.classList.add("hidden"));
  btnEditorSave.addEventListener("click", saveEditorContent);

  // Modal Closures: Register
  btnOpenRegisterModal.addEventListener("click", () => registerModal.classList.remove("hidden"));
  btnCloseRegisterModal.addEventListener("click", () => registerModal.classList.add("hidden"));
  btnRegisterCancel.addEventListener("click", () => registerModal.classList.add("hidden"));
  btnRegisterSubmit.addEventListener("click", submitNewToolRegistration);

  // Modal Closures: Telemetry
  if (btnCloseTelemetryModal) btnCloseTelemetryModal.addEventListener("click", () => telemetryModal.classList.add("hidden"));
  if (btnCloseTelemetryModalBottom) btnCloseTelemetryModalBottom.addEventListener("click", () => telemetryModal.classList.add("hidden"));

  // Modal Closures: Hash Fingerprint
  if (btnCloseHashModal) btnCloseHashModal.addEventListener("click", () => hashModal.classList.add("hidden"));
  if (btnCloseHashModalBottom) btnCloseHashModalBottom.addEventListener("click", () => hashModal.classList.add("hidden"));
  if (btnHashModalEdit) {
    btnHashModalEdit.addEventListener("click", () => {
      hashModal.classList.add("hidden");
      if (window._currentHashTool) openCodeEditor(window._currentHashTool);
    });
  }

  // Diff Modal Actions
  btnActionApprove.addEventListener("click", approveCurrentToolUpdate);
  btnActionRevert.addEventListener("click", revertCurrentTool);

  // Quick Prompt Chips
  document.querySelectorAll(".prompt-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      chatInput.value = btn.dataset.query;
      chatForm.dispatchEvent(new Event("submit"));
    });
  });
}

// Fetch Ollama models
async function fetchModels() {
  try {
    const res = await fetch("/api/models");
    const data = await res.json();
    if (data.models && data.models.length > 0) {
      modelSelector.innerHTML = "";
      data.models.forEach(model => {
        const opt = document.createElement("option");
        opt.value = model;
        opt.textContent = model;
        if (model.includes("qwen2.5-coder:7b") || model === data.default) {
          opt.selected = true;
        }
        modelSelector.appendChild(opt);
      });
    }
  } catch (err) {
    console.error("Failed to query Ollama models:", err);
  }
}

// Fetch registered tools & live hashes
async function fetchTools() {
  try {
    const res = await fetch("/api/tools");
    const data = await res.json();
    activeTools = data.tools || {};
    renderToolsList(activeTools);
  } catch (err) {
    console.error("Failed to query tool registry:", err);
  }
}

// Render Tools in Left Panel (Cleaned: No explicit hash clutter; popup button provided)
function renderToolsList(tools) {
  toolsInventory.innerHTML = "";

  if (Object.keys(tools).length === 0) {
    toolsInventory.innerHTML = `<div style="font-size:11px; color:var(--text-muted);">No tools registered.</div>`;
    return;
  }

  for (const [name, info] of Object.entries(tools)) {
    const card = document.createElement("div");
    const isTampered = info.status === "MUTATION_DETECTED";
    card.className = `tool-entry-card ${isTampered ? "card-tampered" : ""}`;

    const badgeClass = isTampered ? "badge-danger" : "badge-success";
    const statusText = isTampered ? "MUTATION DETECTED" : "VERIFIED";

    card.innerHTML = `
      <div class="card-top">
        <span class="tool-code-title">${name}.py</span>
        <span class="badge ${badgeClass}">${statusText}</span>
      </div>
      <div class="card-button-row">
        <button class="btn-sm btn-outline" onclick="openCodeEditor('${name}')">Inspect / Edit</button>
        <button class="btn-sm btn-outline" onclick="openHashDetailsModal('${name}')" title="Inspect SHA-256 cryptographic fingerprint in popup">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          Fingerprint
        </button>
        ${isTampered ? `<button class="btn-sm btn-danger" onclick="openDiffModal('${name}')">Inspect Diff</button>` : ''}
        ${isTampered ? `<button class="btn-sm btn-outline" onclick="quickRevertTool('${name}')">Revert</button>` : ''}
      </div>
    `;
    toolsInventory.appendChild(card);
  }
}

// Handle Chat Submission
async function handleChatSubmit(e) {
  e.preventDefault();
  const prompt = chatInput.value.trim();
  if (!prompt) return;

  appendUserBubble(prompt);
  chatInput.value = "";
  btnSubmit.disabled = true;

  const loadingBubble = appendLoadingBubble();

  try {
    const selectedModel = modelSelector.value;
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: prompt, model: selectedModel })
    });

    const data = await res.json();
    loadingBubble.remove();

    if (data.blocked_by_security) {
      // Cryptographic hash mismatch blocked execution
      appendBlockedBubble(data);
      appendAudit(`CRITICAL VIOLATION: Execution of '${data.tool_name}' BLOCKED before runtime! Live hash does not match pinned baseline.`, "critical");
      fetchTools();
      openDiffModal(data.tool_name);
    } else if (data.success) {
      appendAssistantBubble(data);
      if (data.tool_calls && data.tool_calls.length > 0) {
        data.tool_calls.forEach(tc => {
          appendAudit(`TOOL EXECUTION: '${tc.tool_name}' executed in ${tc.execution_time_ms}ms. Live SHA-256 byte check passed.`, "verified");
          if (tc.sanitized) {
            appendAudit(`OUTPUT SANITIZER: Redacted ${tc.threats.length} untrusted prompt injection pattern(s) from '${tc.tool_name}'.`, "warning");
          }
        });
      }
      fetchTools();
    } else {
      appendAssistantPlain(data.error || "Agent communication error.");
      appendAudit(`Agent error: ${data.error}`, "critical");
    }

    if (data.audit_events) {
      data.audit_events.forEach(ev => {
        if (ev.type === "HIJACK_QUARANTINE") {
          appendAudit(`HIJACK SCANNER: Quarantined tool '${ev.tool}'. Description contains cross-tool override directive!`, "warning");
        }
      });
    }

  } catch (err) {
    loadingBubble.remove();
    appendAssistantPlain(`Connection failure: ${err.message}`);
    appendAudit(`Proxy error: ${err.message}`, "critical");
  } finally {
    btnSubmit.disabled = false;
  }
}

// Chat UI Bubbles
function appendUserBubble(text) {
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-user";
  bubble.innerHTML = `
    <div class="bubble-meta">OPERATOR</div>
    <div class="bubble-content">${escapeHtml(text)}</div>
  `;
  chatStream.appendChild(bubble);
  chatStream.scrollTop = chatStream.scrollHeight;
}

function appendLoadingBubble() {
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-assistant";
  bubble.innerHTML = `
    <div class="bubble-meta">ASSISTANT &bull; PROCESSING</div>
    <div class="bubble-content">
      <span class="pulse-indicator" style="display:inline-block; vertical-align:middle; margin-right:8px;"></span>
      Reasoning and evaluating query with Ollama...
    </div>
  `;
  chatStream.appendChild(bubble);
  chatStream.scrollTop = chatStream.scrollHeight;
  return bubble;
}

function appendAssistantPlain(text) {
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-assistant";
  bubble.innerHTML = `
    <div class="bubble-meta">ASSISTANT &bull; DIRECT RESPONSE</div>
    <div class="bubble-content">${escapeHtml(text)}</div>
  `;
  chatStream.appendChild(bubble);
  chatStream.scrollTop = chatStream.scrollHeight;
}

// Assistant Response Bubble: Clean text with button icon for telemetry popup (No raw data dump)
function appendAssistantBubble(data) {
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-assistant";

  const hasTools = data.tool_calls && data.tool_calls.length > 0;
  const metaText = hasTools 
    ? "ASSISTANT &bull; VERIFIED MCP TOOL EXECUTION" 
    : "ASSISTANT &bull; DIRECT RESPONSE (NO TOOLS INVOKED)";

  let telemetryHtml = "";
  if (hasTools) {
    const execId = "exec_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7);
    window._telemetryHistory[execId] = data.tool_calls;

    telemetryHtml += `<div class="tool-call-pills-row">`;
    data.tool_calls.forEach((tc, idx) => {
      const isSanitized = tc.sanitized;
      telemetryHtml += `
        <button class="btn-telemetry-pill" onclick="openTelemetryModal('${execId}', ${idx})" title="Click to view execution arguments and verified output data in popup">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="4 17 10 11 4 5"></polyline>
            <line x1="12" y1="19" x2="20" y2="19"></line>
          </svg>
          <span>EXEC: <strong>${escapeHtml(tc.tool_name)}</strong> (${tc.execution_time_ms}ms)</span>
          <span class="badge badge-success">[AUTHENTICATED]</span>
          ${isSanitized ? `<span class="badge badge-warning">[SANITIZED]</span>` : ''}
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.75; margin-left:2px;">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
            <polyline points="15 3 21 3 21 9"></polyline>
            <line x1="10" y1="14" x2="21" y2="3"></line>
          </svg>
        </button>
      `;
    });
    telemetryHtml += `</div>`;
  }

  bubble.innerHTML = `
    <div class="bubble-meta">${metaText}</div>
    <div class="bubble-content">
      <div>${formatMarkdown(data.response || "")}</div>
      ${telemetryHtml}
    </div>
  `;
  chatStream.appendChild(bubble);
  chatStream.scrollTop = chatStream.scrollHeight;
}

function appendBlockedBubble(data) {
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-assistant";
  const toolName = data.tool_name || "unknown";

  bubble.innerHTML = `
    <div class="bubble-meta" style="color:var(--status-tampered-text);">SECURITY PROXY &bull; EXECUTION HALTED</div>
    <div class="bubble-content">
      <div class="halt-alert-box">
        <strong>[SECURITY_INCIDENT: HASH_MISMATCH_HALT]</strong>
        The live file on disk for <code>${escapeHtml(toolName)}.py</code> does not match the pinned approval hash.
        <br><br>
        <button class="inspect-diff-link" onclick="openDiffModal('${escapeHtml(toolName)}')">
          INSPECT DIFF
        </button>
      </div>
    </div>
  `;
  chatStream.appendChild(bubble);
  chatStream.scrollTop = chatStream.scrollHeight;
}

// Modal 4: Telemetry Popup Viewer
window.openTelemetryModal = function(execId, idx) {
  const records = window._telemetryHistory[execId];
  if (!records || !records[idx]) return;
  const tc = records[idx];

  telemetryModalToolName.textContent = tc.tool_name + ".py";
  telemetryModalLatency.textContent = tc.execution_time_ms + " ms (Disk + Host Exec)";

  if (tc.sanitized) {
    telemetryModalStatusBadge.className = "status-marker marker-alert";
    telemetryModalStatusBadge.textContent = "[UNTRUSTED DATA SANITIZED]";
  } else {
    telemetryModalStatusBadge.className = "status-marker";
    telemetryModalStatusBadge.textContent = "[AUTHENTICATED: SHA-256 MATCH]";
  }

  try {
    telemetryModalArguments.textContent = JSON.stringify(tc.arguments, null, 2);
  } catch(e) {
    telemetryModalArguments.textContent = String(tc.arguments);
  }

  try {
    telemetryModalOutput.textContent = JSON.stringify(tc.sanitized_output, null, 2);
  } catch(e) {
    telemetryModalOutput.textContent = String(tc.sanitized_output);
  }

  telemetryModalProof.textContent = `Cryptographic proof: Targeted byte-level SHA-256 verification of 'tools/${tc.tool_name}.py' matched approved baseline on disk prior to runtime invocation.`;

  telemetryModal.classList.remove("hidden");
};

// Modal 5: Hash Fingerprint Popup Viewer
window.openHashDetailsModal = function(toolName) {
  window._currentHashTool = toolName;
  const tool = activeTools[toolName];
  if (!tool) return;

  const isTampered = tool.status === "MUTATION_DETECTED";
  hashModalStatusBadge.className = `status-marker ${isTampered ? "marker-alert" : ""}`;
  hashModalStatusBadge.textContent = isTampered ? "[MUTATION DETECTED]" : "[VERIFIED]";

  hashModalFilePath.value = tool.file_path || `tools/${toolName}.py`;
  hashModalBaselineVal.textContent = tool.baseline_hash || "UNREGISTERED";
  hashModalLiveVal.textContent = tool.live_hash || "N/A";

  if (isTampered) {
    hashModalLiveVal.className = "hash-text hash-altered";
    hashModalStatusDesc.textContent = "CRITICAL: Current disk byte fingerprint differs from approved baseline. Execution is locked until re-approval or revert.";
    hashModalStatusDesc.style.color = "var(--red-text)";
  } else {
    hashModalLiveVal.className = "hash-text hash-clean";
    hashModalStatusDesc.textContent = "Baseline hash matches disk bytes identically. Tool is authenticated and authorized for runtime execution.";
    hashModalStatusDesc.style.color = "var(--orange-text)";
  }

  hashModal.classList.remove("hidden");
};

// Code Editor Modal
window.openCodeEditor = async function(toolName) {
  currentActiveTool = toolName;
  try {
    const res = await fetch(`/api/tools/${toolName}/content`);
    const data = await res.json();
    editorFilePath.textContent = data.file_path;
    editorTextarea.value = data.live_content;

    const isTampered = data.verification.status === "MUTATION_DETECTED";
    editorLiveStatusPill.className = `badge ${isTampered ? "badge-danger" : "badge-success"}`;
    editorLiveStatusPill.textContent = isTampered ? "MUTATION DETECTED" : "VERIFIED";

    editorModal.classList.remove("hidden");
  } catch (err) {
    alert("Failed to load tool content: " + err.message);
  }
};

async function saveEditorContent() {
  const code = editorTextarea.value;
  try {
    const res = await fetch("/api/tools/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_name: currentActiveTool, code_content: code })
    });
    const data = await res.json();
    if (data.success) {
      appendAudit(`FILE MODIFIED: Updated '${currentActiveTool}.py' on disk. Live SHA-256 recomputed.`, "info");
      editorModal.classList.add("hidden");
      fetchTools();
      if (data.verification.status === "MUTATION_DETECTED") {
        openDiffModal(currentActiveTool);
      }
    } else {
      alert("Save failed: " + (data.detail || data.error));
    }
  } catch (err) {
    alert("Failed to save file: " + err.message);
  }
}

// Unified Diff Modal
window.openDiffModal = function(toolName) {
  currentActiveTool = toolName;
  const tool = activeTools[toolName];
  if (!tool) return;

  diffBaselineHash.textContent = tool.baseline_hash || "N/A";
  diffLiveHash.textContent = tool.live_hash || "N/A";
  diffFileTarget.textContent = tool.file_path || `tools/${toolName}.py`;

  const rawDiff = tool.diff || "No line diff available (or identical binary).";
  diffPreElement.innerHTML = renderColorDiff(rawDiff);

  diffModal.classList.remove("hidden");
};

function renderColorDiff(diffStr) {
  const lines = diffStr.split("\n");
  return lines.map(line => {
    if (line.startsWith("+") && !line.startsWith("+++")) {
      return `<span class="diff-added">${escapeHtml(line)}</span>`;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      return `<span class="diff-removed">${escapeHtml(line)}</span>`;
    } else if (line.startsWith("@@")) {
      return `<span class="diff-meta">${escapeHtml(line)}</span>`;
    }
    return `<span>${escapeHtml(line)}</span>`;
  }).join("\n");
}

// Re-approval & Revert
async function approveCurrentToolUpdate() {
  try {
    const res = await fetch("/api/tools/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_name: currentActiveTool })
    });
    const data = await res.json();
    if (data.success) {
      appendAudit(`LEGITIMATE UPDATE APPROVED: Pinned new baseline SHA-256 for '${currentActiveTool}'.`, "verified");
      diffModal.classList.add("hidden");
      fetchTools();
    }
  } catch (err) {
    alert("Approval failed: " + err.message);
  }
}

async function revertCurrentTool() {
  await quickRevertTool(currentActiveTool);
  diffModal.classList.add("hidden");
}

window.quickRevertTool = async function(toolName) {
  try {
    const res = await fetch("/api/tools/revert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_name: toolName })
    });
    const data = await res.json();
    if (data.success) {
      appendAudit(`RESTORED SNAPSHOT: '${toolName}.py' reverted to last approved baseline on disk.`, "info");
      fetchTools();
    }
  } catch (err) {
    alert("Revert failed: " + err.message);
  }
};

// Register New Tool Submission
async function submitNewToolRegistration() {
  const name = newToolNameInput.value.trim();
  const code = newToolCodeTextarea.value.trim();

  if (!name || !code) {
    alert("Please provide both a tool name and Python code.");
    return;
  }

  try {
    const res = await fetch("/api/tools/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_name: name, code_content: code })
    });
    const data = await res.json();
    if (data.success) {
      appendAudit(`TOOL REGISTERED: '${name}.py' added to tools directory and cryptographically pinned.`, "verified");
      registerModal.classList.add("hidden");
      newToolNameInput.value = "";
      newToolCodeTextarea.value = "";
      fetchTools();
    } else {
      alert("Registration failed: " + (data.detail || "Unknown error"));
    }
  } catch (err) {
    alert("Failed to register tool: " + err.message);
  }
}

// Audit Logging (Console)
function appendAudit(msg, level = "info") {
  console.log(`[MCP-AUDIT-${level.toUpperCase()}] ${msg}`);
}

// Utilities
function escapeHtml(str) {
  if (!str) return "";
  return str.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatMarkdown(text) {
  let formatted = escapeHtml(text);
  formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
  formatted = formatted.replace(/\n/g, '<br>');
  return formatted;
}
