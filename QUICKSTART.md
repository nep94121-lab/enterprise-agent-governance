# ⚡ Enterprise Agent Governance Framework — Quick Start Guide (QUICKSTART.md)

> **Integrate 3-Tier Multi-Agent Governance, Physical Runtime Hooks & Dynamic Hardware Governor in Under 5 Minutes.**

[![Integration Time](https://img.shields.io/badge/Setup%20Time-5%20Minutes-brightgreen.svg)](#)
[![Supported Platforms](https://img.shields.io/badge/Platforms-Antigravity%20%7C%20Claude%20Code%20%7C%20Cursor%20%7C%20Custom%20CLI-blue.svg)](#)
[![Compatibility](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-orange.svg)](#)

---

## 📑 Quick Navigation

1. [Prerequisites & System Requirements](#1-prerequisites--system-requirements)
2. [Step 1: Install Core Python Dependencies](#2-step-1-install-core-python-dependencies)
3. [Step 2: Copy Governance Repository to Your Project](#3-step-2-copy-governance-repository-to-your-project)
4. [Step 3: Platform Integration Guides](#4-step-3-platform-integration-guides)
   - [Option A: Google Antigravity / Gemini CLI](#option-a-google-antigravity--gemini-cli)
   - [Option B: Anthropic Claude Code](#option-b-anthropic-claude-code)
   - [Option C: Cursor & RooCode IDEs](#option-c-cursor--roocode-ides)
   - [Option D: Custom Python Agent Frameworks (LangGraph / AutoGen)](#option-d-custom-python-agent-frameworks-langgraph--autogen)
5. [Step 4: Execute Self-Test Verification Suite](#5-step-4-execute-self-test-verification-suite)
6. [Step 5: Run Your First Multi-Agent Task](#6-step-5-run-your-first-multi-agent-task)
7. [Troubleshooting & Common Questions](#7-troubleshooting--common-questions)

---

## 1. Prerequisites & System Requirements

EAGF runs seamlessly across all major operating systems:
- **Operating System:** Windows 10/11, Linux (Ubuntu, Debian, Fedora, Arch), macOS (Apple Silicon & Intel).
- **Python Version:** Python 3.10 or higher.
- **Hardware Footprint:** Minimal (< 20MB disk space, < 2% CPU overhead). Automatically scales from 2-core laptops to 128-core servers.

---

## 2. Step 1: Install Core Python Dependencies

The governance framework uses standard, lightweight libraries with zero heavy C++ bindings:

```bash
pip install psutil pydantic
```

*(Optional for advanced static code inspection: `pip install ruff`)*

---

## 3. Step 2: Copy Governance Repository to Your Project

Clone or copy the `enterprise_agent_governance/` directory into your project root:

```bash
# Example directory structure
my_project/
├── enterprise_agent_governance/
│   ├── rules/
│   ├── hooks/
│   ├── hook_utils/
│   └── templates/
├── src/
└── tests/
```

---

## 4. Step 3: Platform Integration Guides

### Option A: Google Antigravity / Gemini CLI

1. **Register Hooks in Antigravity Configuration:**
   Add or point the hooks configuration to `hooks.json` in your Antigravity config file (`~/.gemini/antigravity/config.json` or project settings):

   ```json
   {
     "governance": {
       "enabled": true,
       "hooks_manifest": "./enterprise_agent_governance/hooks/hooks.json",
       "hardware_governor": {
         "enabled": true,
         "mode": "auto"
       }
     }
   }
   ```

2. **Set System Rules Path:**
   Point the root agent rules to `enterprise_agent_governance/rules/AGENTS.md`.

---

### Option B: Anthropic Claude Code

1. **Set Environment Variable:**
   Export the hooks manifest path before launching Claude Code:

   ```bash
   # On Linux / macOS
   export CLAUDE_AGENT_HOOKS="$(pwd)/enterprise_agent_governance/hooks/hooks.json"

   # On Windows (PowerShell)
   $env:CLAUDE_AGENT_HOOKS = "$((Get-Location).Path)\enterprise_agent_governance\hooks\hooks.json"
   ```

2. **Configure Prompt Architecture:**
   Copy `enterprise_agent_governance/rules/AGENTS.md` to `CLAUDE.md` in your project root. Claude Code will automatically ingest the No-Code and Turn-1 Canary invariants.

---

### Option C: Cursor & RooCode IDEs

1. **Configure Custom System Prompts:**
   Add the content of `enterprise_agent_governance/README_AI.md` to your `.cursorrules` or `.roomodes` file.

2. **Enable Pre-Execution Hooks:**
   If using extension-based command hooks, link `run_command` and file edit triggers to `hooks/hooks_scripts/dangerous_command_guard.py` and `scope_boundary_enforcer.py`.

---

### Option D: Custom Python Agent Frameworks (LangGraph / AutoGen)

You can invoke EAGF physical hooks directly via the Python middleware:

```python
from enterprise_agent_governance.hooks.hooks_scripts.scope_boundary_enforcer import enforce_scope_boundary
from enterprise_agent_governance.hooks.hooks_scripts.dangerous_command_guard import validate_command_safety

# Pre-Tool execution hook wrapper
def pre_tool_hook(tool_name: str, tool_args: dict, agent_id: str):
    if tool_name in ["write_to_file", "replace_file_content"]:
        enforce_scope_boundary(target_path=tool_args["path"], agent_id=agent_id)
    elif tool_name == "run_command":
        validate_command_safety(command=tool_args["command"], agent_id=agent_id)
```

---

## 5. Step 4: Execute Self-Test Verification Suite

Run the built-in diagnostic test to confirm your hardware profile and hook event listeners are ready:

```bash
# 1. Test Hardware Auto-Sensing
python enterprise_agent_governance/hook_utils/hardware_sensor.py

# Expected Output:
# [HARDWARE_SENSOR] Detected 4 physical cores / 8 logical threads.
# [HARDWARE_SENSOR] Total Host RAM: 24.0 GB.
# [HARDWARE_SENSOR] Dual-Pool Allocation:
#   - Pool 1 (Cloud Concurrency Cap): 20 subagents
#   - Pool 2 (Local Burst Slots): 3 concurrent slots
#   - Status: OPTIMAL_READY

# 2. Test Dangerous Command Guard (Should trigger HARD DENY)
python enterprise_agent_governance/hooks/hooks_scripts/dangerous_command_guard.py "rm -rf /"

# Expected Output:
# 🚨 [HARD DENY] DangerousCommandGuard blocked command: 'rm -rf /'. Exit code 1.
```

---

## 6. Step 5: Run Your First Multi-Agent Task

1. **Start a New Session:**
   Launch your agent CLI or chat interface.

2. **Give the High-Level Intent:**
   > *"Build a robust user authentication module with JWT, rate limiting, and 100% test coverage."*

3. **Observe EAGF in Action:**
   - **Tier 1 Executive Agent:** Compiles `request_artifact.md` without writing a single line of code.
   - **Tier 2 PM Orchestrator:** Allocates `progress.md` with Exclusive File Ownership and executes Phase 1 through Phase 4.
   - **Tier 3 Workers:** Spawn in parallel (Backend Developer, AppSec Sentinel, QA Challenger), respect Turn-1 Canary verification, execute atomic file edits, and pass the ARCH-DOC-03 Multi-Auditor Panel.
   - **Completion:** A clean 5-part `handoff.md` is generated, and all background tasks are automatically cleaned up.

---

## 7. Troubleshooting & Common Questions

### Q1: An agent was rejected with `HARD DENY: CANARY_VERIFICATION_MISSING`. What happened?
**Reason:** The agent attempted to write code or run commands before reading its role rules and recording `CANARY_VERIFIED: §...` in `progress.md`.
**Fix:** Ensure the subagent prompt contains the `<turn1_enforced_gate>` block pointing to its assigned `rules/rules_by_role/[role]/[ROLE]_RULES.md`.

### Q2: Why are heavy test commands queuing up instead of executing all at once?
**Reason:** Pool 2 Local Burst Compute Semaphore is active. It prevents host CPU exhaustion by queuing heavy commands into physical-core-scaled slots.
**Status:** This is intentional. The 3-Zone CPU Governor prevents host freezing and laptop fan screaming.

### Q3: An agent received `HARD DENY: FILE_OWNERSHIP_VIOLATION`. How do I resolve it?
**Reason:** The worker attempted to edit a file not assigned to it in `progress.md`.
**Fix:** Update the Exclusive File Ownership table in `progress.md` before the worker performs the modification.

---

> 🚀 **Ready to scale!** For in-depth architectural details, see [ARCHITECTURE.md](ARCHITECTURE.md). For file structure mappings, see [DIRECTORY_GUIDE.md](DIRECTORY_GUIDE.md).
