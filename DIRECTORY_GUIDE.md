# 📂 Enterprise Agent Governance Framework — Directory & Repository Guide (DIRECTORY_GUIDE.md)

> **Complete Structural Blueprint, Directory Mapping, File Responsibilities & Access Permission Matrix.**

[![Documentation Status](https://img.shields.io/badge/Directory%20Guide-Standardized-brightgreen.svg)](#)
[![Roles Mapped](https://img.shields.io/badge/Roles%20Mapped-14%20Specialized%20Roles-blueviolet.svg)](#)
[![Hooks Registered](https://img.shields.io/badge/Hooks%20Registered-52%20Physical%20Hooks-blue.svg)](#)

---

## 📑 Table of Contents

1. [Repository Tree Structure](#1-repository-tree-structure)
2. [Root Documentation & Core Entry Points](#2-root-documentation--core-entry-points)
3. [The `rules/` Directory — Hierarchical Role Governance](#3-the-rules-directory--hierarchical-role-governance)
4. [The `hooks/` & `hooks_scripts/` Directory — 52 Physical Interceptors](#4-the-hooks--hooks_scripts-directory--52-physical-interceptors)
5. [The `hook_utils/` Directory — Hardware Auto-Sensing & Telemetry](#5-the-hook_utils-directory--hardware-auto-sensing--telemetry)
6. [The `templates/` Directory — Standardized Task Contracts & Prompts](#6-the-templates-directory--standardized-task-contracts--prompts)
7. [Role-to-File Permitted Access Matrix](#7-role-to-file-permitted-access-matrix)

---

## 1. Repository Tree Structure

Below is the complete architectural layout of the `enterprise_agent_governance` repository:

```
enterprise_agent_governance/
├── README.md                      # Global International Overview (English)
├── README_VN.md                   # Comprehensive Operating Guide (Tiếng Việt)
├── README_AI.md                   # Machine-Readable AI Turn-1 Onboarding Guide
├── ARCHITECTURE.md                # In-depth Technical Architecture & Mermaid Diagrams
├── DIRECTORY_GUIDE.md             # Complete Repository Structure & File Index (This File)
├── QUICKSTART.md                  # 5-Minute Fast Integration & Verification Manual
├── LICENSE                        # Official MIT License (2026)
│
├── rules/                         # Hierarchical Role Rules & Constitutions
│   ├── AGENTS.md                  # Tier 1 Executive Agent Constitution (Zero-Code Invariant)
│   └── rules_by_role/             # Tier 2 & Tier 3 Role Rules (14 Roles)
│       ├── appsec_sentinel/       # AppSec Sentinel Rules
│       ├── backend_developer/     # Backend Developer Rules
│       ├── codebase_explorer/     # Codebase Explorer Rules (Read-Only)
│       ├── data_ml_engineer/      # Data & ML Engineer Rules
│       ├── devops_security/       # DevOps & Infrastructure Rules
│       ├── frontend_developer/    # Frontend Developer Rules
│       ├── lead_watchdog/         # Lead Fleet Telemetry Watchdog Rules
│       ├── mobile_app_developer/  # Mobile Application Developer Rules
│       ├── pm_challenger/         # PM Plan Reviewer & Challenger Rules
│       ├── pm_orchestrator/       # Tier 2 PM Orchestrator Rules (7 Phase Gates)
│       ├── qa_challenger/         # Adversarial QA & Anti-Cheat Rules
│       ├── state_checkpoint_curator/ # Saga Transaction & Rollback Curator Rules
│       ├── tech_lead_auditor/     # Tech Lead Auditor & 10-Layer Pre-Flight Rules
│       └── watchdog_inspector/    # Independent Telemetry Inspector Rules
│
├── hooks/                         # Hook Registries & Runtime Configurations
│   ├── hooks.json                 # Master Hook Event Bus Registry (52 Hooks)
│   ├── dynamic_limits.json        # Dynamic Resource & Concurrency Configs
│   └── hooks_scripts/             # 52 Physical Python Interceptor Scripts
│       ├── dangerous_command_guard.py
│       ├── scope_boundary_enforcer.py
│       ├── turn1_enforced_gate_guard.py
│       ├── burst_execution_guard.py
│       ├── anti_sequential_guard.py
│       ├── diff_security_inspector.py
│       ├── secret_and_pii_scanner.py
│       ├── anti_cheat_test_auditor.py
│       └── ... (Full suite of 52 physical interceptor scripts)
│
├── hook_utils/                    # Core Utilities & Telemetry Engines
│   ├── hardware_sensor.py         # Dynamic CPU/RAM OS Detection & Auto-Sizing
│   ├── cpu_governor.py            # psutil 3-Zone Dynamic Speed Controller
│   ├── telemetry_logger.py        # SQLite / JSONL Audit Event Streamer
│   └── token_budget_counter.py    # Context Window Hygiene & Token Estimator
│
└── templates/                     # Standardized XML Artifacts & Prompt Templates
    ├── DISPATCH_TEMPLATE.md       # 7-Section XML Task Contract Template
    ├── BRIEFING_TEMPLATE.md       # Context & Architectural Interface Template
    ├── PROGRESS_TEMPLATE.md       # Progress Tracking & Exclusive File Ownership Table
    ├── HANDOFF_TEMPLATE.md        # Standardized 5-Section Handoff Template
    ├── explorer_prompt.md         # Read-Only Phase 2 Explorer Prompt
    ├── worker_prompt.md           # Implementation Phase 5 Worker Prompt
    ├── watchdog_prompt.md         # Fleet Telemetry Watchdog Prompt
    ├── reviewer_prompt.md         # Architecture Reviewer Prompt
    ├── challenger_prompt.md       # Adversarial QA Challenger Prompt
    └── auditor_prompt.md          # 10-Layer Pre-Flight Auditor Prompt
```

---

## 2. Root Documentation & Core Entry Points

| File Name | Intended Audience | Core Purpose |
|---|---|---|
| `README.md` | Global Open-Source Community | High-level architectural overview, 3-Tier model, Dual-Pool concurrency, comparison matrix. |
| `README_VN.md` | Vietnamese Engineers & Enterprises | Detailed translation, enterprise rationales, operating instructions in Vietnamese. |
| `README_AI.md` | Autonomous AI Agents & LLMs | Machine-readable onboarding protocol, Turn-1 Canary verification, No-Code invariants, handoff JSON schema. |
| `ARCHITECTURE.md` | Architects & Tech Leads | Exhaustive architectural blueprints with 5 comprehensive Mermaid diagrams and formal mathematical definitions. |
| `DIRECTORY_GUIDE.md` | All Users & Agents | Complete breakdown of every folder, script, template, and permission mapping. |
| `QUICKSTART.md` | Developers Integrating EAGF | 5-minute setup guide for Google Antigravity, Claude Code, Cursor, and custom CLI environments. |
| `LICENSE` | Legal & Governance | Standard MIT License for permissive open-source usage. |

---

## 3. The `rules/` Directory — Hierarchical Role Governance

The `rules/` directory houses the operational constitutions for all agent levels:

### 1. `rules/AGENTS.md` (Tier 1 Executive Agent)
- Defines the **No-Code Invariant**: Tier 1 is physically blocked from modifying source code.
- Establishes rules for interacting with human users in concise Vietnamese/English.
- Defines task contract packaging into `request_artifact.md`.

### 2. `rules/rules_by_role/` (14 Specialized Engineering Roles)
Each role has its own dedicated folder containing a `[ROLE]_RULES.md` file:
- **`pm_orchestrator/PM_RULES.md`**: Enforces the 7 Phase Gates, Exclusive File Ownership allocation, rolling batch dispatching, and PM no-code invariants.
- **`backend_developer/BACKEND_RULES.md`**: Mandates parameterized queries (§3), PII protection (§1), async event loop safety (§6), and ownership IDOR filters (§24).
- **`frontend_developer/FRONTEND_RULES.md`**: Enforces component isolation, accessibility, responsive styling, and zero raw PII rendering.
- **`appsec_sentinel/APPSEC_RULES.md`**: Defines OWASP Top 10 automated scans, secret hunting, and network egress rules.
- **`qa_challenger/QA_RULES.md`**: Mandates adversarial test fuzzing, negative boundary testing, and detection of empty assertion fraud.
- **`codebase_explorer/EXPLORER_RULES.md`**: Strict **Read-Only** rules forbidding any write tools.
- **`tech_lead_auditor/TECH_LEAD_RULES.md`**: Enforces the 10-Layer Pre-Flight verification standard before merge authorization.
- **`devops_security/DEVOPS_RULES.md`**: Infrastructure-as-code, Docker least-privilege, and CI/CD pipeline integrity.
- **`lead_watchdog/WATCHDOG_RULES.md`**: Fleet telemetry tracking, infinite loop interception, and context window saturation alarms.
- **`state_checkpoint_curator/STATE_RULES.md`**: Saga pattern transaction management and Git time-travel rollback checkpoints.
- **`data_ml_engineer/DATA_RULES.md`**: Machine learning model testing, data pipeline sanitization, and BigQuery / SQL safety.
- **`mobile_app_developer/MOBILE_RULES.md`**: Mobile responsive patterns, offline-first caching, and cross-platform native hooks.
- **`pm_challenger/PM_CHALLENGER_RULES.md`**: Independent adversarial review of PM execution plans to prevent design flaws.
- **`watchdog_inspector/INSPECTOR_RULES.md`**: Independent health monitor sampling process runtimes and detecting zombie commands.

---

## 4. The `hooks/` & `hooks_scripts/` Directory — 52 Physical Interceptors

Physical hooks intercept tool proposals before (`PreToolUse`) and after (`PostToolUse`) execution.

### Master Hook Configuration (`hooks/hooks.json`):
Registers all 52 hooks with event triggers, regex matchers, priority levels (P0, P1, P2), and Python execution paths.

### Categorization of the 52 Hooks:

#### Group 1: Security & Blast Radius Isolation (P0 Priority)
- `scope_boundary_enforcer.py`: Intercepts `write_to_file` and `replace_file_content`; blocks modifications to unassigned files.
- `dangerous_command_guard.py`: Intercepts `run_command`; aborts `rm -rf /`, `mkfs`, `drop database`, forkbombs, etc.
- `turn1_enforced_gate_guard.py`: Blocks any code modifications before Turn-1 Canary verification.
- `anti_path_traversal.py`: Blocks directory traversal attacks (`../../`).
- `secret_and_pii_scanner.py`: Inspects written content; redacts API keys, JWTs, and citizen identification strings.

#### Group 2: Concurrency, Performance & Hardware Governance (P1 Priority)
- `burst_execution_guard.py`: Enforces local burst compute semaphore based on host CPU load.
- `anti_sequential_guard.py`: Prevents single-agent monolithic execution on parallelizable workloads.
- `rolling_batch_regulator.py`: Regulates subagent generation into chunks of $\le 20$.
- `zombie_process_sweeper.py`: Terminates abandoned terminal processes after 180 seconds.
- `cpu_thermal_guard.py`: Inserts dynamic 1.0s cooling delays when host CPU exceeds 85%.

#### Group 3: Code Integrity, Anti-Cheat & Quality Assurance (P2 Priority)
- `diff_security_inspector.py`: Performs Python AST parsing to block hidden dynamic imports or malicious eval.
- `anti_cheat_test_auditor.py`: Scans test suites for dummy asserts (`assert True`), commented-out tests, or fake mocks.
- `goal_drift_telemetry_tracker.py`: Tracks cumulative edits against `request_artifact.md`.
- `clean_handoff_validator.py`: Validates that `handoff.md` satisfies all 5 required structural sections.

---

## 5. The `hook_utils/` Directory — Hardware Auto-Sensing & Telemetry

Core Python helper modules supporting the runtime hook infrastructure:

- **`hardware_sensor.py`**: Queries host OS via `psutil` and `os.cpu_count()` to determine physical vs logical cores, total memory, and compute capacity. Automatically configures slot limits for Windows, Linux, and macOS.
- **`cpu_governor.py`**: Implements the 3-Zone CPU speed governor (Acceleration <60%, Golden 60-85%, Thermal Protection >85%).
- **`telemetry_logger.py`**: Writes structured telemetry records to `trajectory.db` and `audit_log.jsonl` for compliance auditing.
- **`token_budget_counter.py`**: Estimates context window consumption and alerts PMs when approaching the 40 tool-call handoff threshold.

---

## 6. The `templates/` Directory — Standardized Task Contracts & Prompts

Standardized artifacts ensuring predictable inter-agent communication:

- **`DISPATCH_TEMPLATE.md`**: Structured XML template containing `<metadata>`, `<turn1_enforced_gate>`, `<context>`, `<task_description>`, `<constraints>`, `<dependencies>`, and `<acceptance_criteria>`.
- **`BRIEFING_TEMPLATE.md`**: Provides technical context, interface contracts, and prerequisites for subagents.
- **`PROGRESS_TEMPLATE.md`**: Standard progress tracker including the Canary token header and the Exclusive File Ownership table.
- **`HANDOFF_TEMPLATE.md`**: 5-part self-contained handoff format plus JSON telemetry schema.
- **Role Prompts**: Standardized XML prompts (`explorer_prompt.md`, `worker_prompt.md`, etc.) for seamless subagent dispatch.

---

## 7. Role-to-File Permitted Access Matrix

To guarantee Zero Write Collisions, the framework establishes immutable file access boundaries:

| File / Directory Pattern | Tier 1 (Executive) | Tier 2 (PM Orchestrator) | Tier 3 (Dev Workers) | Tier 3 (Auditors & QA) |
|---|:---:|:---:|:---:|:---:|
| `request_artifact.md` | **WRITE** | READ | READ | READ |
| `progress.md`, `GATE_STATUS.md` | READ | **WRITE** | READ | READ |
| `src/backend/**` | ❌ BLOCKED | ❌ BLOCKED | **EXCLUSIVE WRITE** | READ |
| `src/frontend/**` | ❌ BLOCKED | ❌ BLOCKED | **EXCLUSIVE WRITE** | READ |
| `tests/adversarial/**` | ❌ BLOCKED | ❌ BLOCKED | ❌ BLOCKED | **EXCLUSIVE WRITE** |
| `hooks/**`, `hooks_scripts/**` | ❌ BLOCKED | ❌ BLOCKED | ❌ BLOCKED | ❌ BLOCKED (DevOps Only) |
| `.agents/[worker_id]/handoff.md` | READ | READ | **WRITE (Own)** | READ |
