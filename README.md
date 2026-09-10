# 🛡️ Enterprise Agent Governance Framework (EAGF)

> **Autonomous Multi-Agent Orchestration, Physical Runtime Safety & Dynamic Hardware Governor for Production AI Systems.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture: 3-Tier Multi-Agent](https://img.shields.io/badge/Architecture-3--Tier%20Hierarchical-blueviolet.svg)](#-3-tier-hierarchical-architecture)
[![Concurrency: Dual-Pool](https://img.shields.io/badge/Concurrency-Dual--Pool%20Asymmetric-brightgreen.svg)](#-dual-pool-concurrency--dynamic-hardware-governor)
[![Safety: 52 Physical Hooks](https://img.shields.io/badge/Guardrails-52%20Physical%20Hooks-red.svg)](#-52-physical-runtime-hooks)
[![Hardware: Dynamic Auto-Sensing](https://img.shields.io/badge/Hardware-Dynamic%20Auto--Sensing-orange.svg)](#-dynamic-hardware-auto-sensing)
[![Documentation: Bilingual](https://img.shields.io/badge/Docs-English%20%7C%20Ti%E1%BA%BFng%20Vi%E1%BB%87t-informational.svg)](README_VN.md)

---

## 🌟 Executive Overview

As Large Language Model (LLM) agents evolve from simple chatbots into autonomous software engineering fleets capable of executing shell commands, modifying codebases, and delegating subagents, **unguarded agent execution poses catastrophic enterprise risks**:
- **Hallucination Cascades:** Autonomous agents believing in erroneous code they generated and compounding errors across hundreds of file edits.
- **Anti-Cheat Violations & Facades:** Agents writing hollow tests (`assert True`), mocking production databases, or hardcoding outputs to bypass verification gates.
- **Runaway Resource Starvation:** Spawning dozens of unthrottled subagents that saturate host CPUs, freeze user interfaces, and exhaust operating system file descriptors.
- **Context Fragmentation:** Bloating LLM context windows with sprawling chat histories, leading to goal drift and severe reasoning degradation.

The **Enterprise Agent Governance Framework (EAGF)** solves these failure modes through **Physical Runtime Interception**, a **3-Tier Hierarchical Governance Model**, an **Asymmetric Dual-Pool Concurrency Governor**, and a deterministic **7 Phase Gates Pipeline**.

Instead of relying on prompt compliance or LLM "goodwill", EAGF enforces safety and architectural integrity at the operating system and tool execution boundary with nanosecond-level physical hooks.

---

## 🏛️ 3-Tier Hierarchical Architecture

EAGF organizes agent fleets into an immutable hierarchy with strict separation of concerns and an enforced **No-Code Policy for Orchestrators**:

```mermaid
graph TD
    classDef executive fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef pm fill:#7c2d12,stroke:#f97316,stroke-width:2px,color:#fff;
    classDef worker fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef hooks fill:#312e81,stroke:#818cf8,stroke-width:2px,color:#fff;

    User["👤 Human Executive / User"] --> Tier1["Tier 1: Top-Level Agent (Executive)"]
    
    subgraph Constitution ["🛡️ Physical Interceptor & Governance Runtime"]
        Hooks["52 Physical Runtime Hooks (PreToolUse / PostToolUse / Stop)"]
    end
    
    Tier1 -->|Generates request_artifact.md & DISPATCH| Tier2["Tier 2: PM Orchestrators (Project Lead)"]
    
    Tier2 -->|7 Phase Gates & Exclusive File Ownership| Tier3["Tier 3: Specialized Workers (14 Roles)"]
    
    subgraph Workers ["Specialized Engineering Sub-Agents (Tier 3)"]
        W1["Backend Developer"]
        W2["Frontend Developer"]
        W3["AppSec Sentinel"]
        W4["DevOps & Security"]
        W5["QA Challenger"]
        W6["Codebase Explorer"]
        W7["Tech Lead Auditor"]
        W8["Watchdog Inspector"]
        W9["Data & ML Engineer"]
        W10["Mobile Developer"]
        W11["Other Specialized Roles..."]
    end

    Tier3 -.-> Workers
    Hooks -.->|Physical Interception| Tier1
    Hooks -.->|Physical Interception| Tier2
    Hooks -.->|Physical Interception| Tier3

    class Tier1 executive;
    class Tier2 pm;
    class Tier3,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11 worker;
    class Hooks hooks;
```

### 1. Tier 1: Top-Level Executive Agent
- **Role:** Direct interface with the human stakeholder.
- **Immutable Invariant:** **ABSOLUTELY FORBIDDEN FROM WRITING OR MODIFYING CODE.**
- **Responsibilities:** Captures user intent, scopes high-level requirements, compiles `request_artifact.md`, and delegates execution entirely to Tier 2 Lead PMs.

### 2. Tier 2: PM Orchestrators (Lead Project Managers)
- **Role:** Technical governance, task decomposition, and milestone coordination.
- **Immutable Invariant:** **STRICTLY FORBIDDEN FROM TOUCHING APPLICATION SOURCE CODE.**
- **Responsibilities:** Manages the 7 Phase Gates, assigns Exclusive File Ownership, schedules staggered rolling worker batches, and synthesizes multi-dimensional audit reports.

### 3. Tier 3: Specialized Technical Workers (14 Dedicated Roles)
- **Role:** Atomic implementation, adversarial verification, security hardening, and telemetry inspection.
- **Key Roles:** `backend_developer`, `frontend_developer`, `appsec_sentinel`, `devops_security`, `qa_challenger`, `codebase_explorer`, `tech_lead_auditor`, `lead_watchdog`, `state_checkpoint_curator`, `data_ml_engineer`, `mobile_app_developer`, `pm_challenger`, `watchdog_inspector`, `codebase_explorer`.
- **Operating Rule:** Each worker operates exclusively on designated files within its assigned blast radius and produces a standardized 5-component handoff report upon completion.

---

## ⚡ Dual-Pool Concurrency & Dynamic Hardware Governor

To achieve maximum throughput without CPU throttling or machine freeze, EAGF decouples cloud inference from local compute execution using an **Asymmetric Dual-Pool Architecture**:

```mermaid
flowchart LR
    subgraph Pool1 ["Pool 1: Cloud Thinking & Tool I/O"]
        P1_Work["Subagent Tasks (N Workloads)"]
        P1_Cap["Concurrency Cap: 20 Parallel Subagents"]
        P1_Batch["Rolling Batches (Batches of <= 20)"]
        P1_Work --> P1_Cap --> P1_Batch
    end

    subgraph Pool2 ["Pool 2: Local Burst Compute Semaphore"]
        P2_Cmd["Heavy Local Commands (build, test, compile)"]
        P2_Sem["Dynamic Slot Semaphore (Scaled to Physical Cores)"]
        P2_Gov["psutil 3-Zone CPU Speed Governor"]
        P2_Cmd --> P2_Sem --> P2_Gov
    end

    subgraph CPU_Zones ["3-Zone CPU Governor"]
        Z1["Acceleration Zone (< 60% CPU)\nInstant slot release"]
        Z2["Golden Zone (60% - 85% CPU)\nOptimal sustained throughput"]
        Z3["Thermal Protection (> 85% CPU)\n1.0s staggered spacing"]
    end

    P2_Gov --> CPU_Zones
```

### Dynamic Hardware Auto-Sensing
Unlike rigid frameworks with hardcoded core limits, EAGF features **dynamic hardware auto-sensing**:
- **Automatic Host Detection:** Dynamically samples physical CPU cores, logical threads, and total available RAM across Windows, Linux, and macOS via `psutil` and `os.cpu_count()`.
- **Elastic Compute Sizing:**
  - *2 to 4 physical cores:* Allocates 2–3 concurrent local burst execution slots.
  - *8 to 16 physical cores:* Scales to 6–12 concurrent burst execution slots.
  - *32 to 128 server cores:* Scales linearly up to 24–48 concurrent burst execution slots while reserving safety headroom for OS stability.
- **Bypass for Lightweight Operations:** Non-compute terminal commands (`git status`, `ls`, `dir`, `echo`) bypass the semaphore queue instantly.
- **Zombie Task Auto-Reclamation:** Background processes running longer than 180 seconds without heartbeat telemetry are automatically terminated and logged.

---

## 🚦 The 7 Phase Gates Workflow

Every technical feature or system modification progresses through a sequential 7-gate lifecycle. Progression is strictly monotonic; skipping gates triggers physical runtime denial (`GATE_ORDER_VIOLATION`):

| Phase Gate | Name | Mandatory Deliverables | Enforced Invariants |
|---|---|---|---|
| **Phase 1** | Contract Ingestion & Scoping | `request_artifact.md` | Fixed input contract; eliminates ambiguous goal drift. |
| **Phase 2** | Codebase Exploration | `codebase_map.md` | Read-only exploration; zero write permissions permitted. |
| **Phase 3** | Architecture Blueprint | `architecture_blueprint.md` | Tech Lead sign-off; ADR compliance and design validation. |
| **Phase 4** | Exclusive File Ownership | `progress.md` (Ownership Table) | 1-to-1 File-to-Worker mapping; prevents concurrent write collisions. |
| **Phase 5** | Implementation & Rolling Execution | Source code, Unit tests | Max 20 subagents/batch; staggered burst queue for test suites. |
| **Phase 6** | Multi-Auditor Panel Verification | `AUDIT_REPORT.md` (ARCH-DOC-03) | 4-layer independent review; score $\ge 90.0/100$, 0 blocking issues. |
| **Phase 7** | Clean Handoff & Resource Cleanup | `handoff.md`, Terminal teardown | 5-section handoff report; 100% background process termination. |

---

## 🛡️ 52 Physical Runtime Hooks

EAGF deploys 52 specialized physical interceptors at critical agent lifecycle events (`PreInvocation`, `PreToolUse`, `PostToolUse`, and `Stop`). If an agent attempts an unauthorized action, the hook aborts execution at the operating system level:

```
[Agent Action Proposed]
         │
         ▼
┌────────────────────────────────────────┐
│ PreToolUse Hook Bus                    │
│ ├─ scope_boundary_enforcer.py          │ ──► Denies edits outside Exclusive Ownership
│ ├─ dangerous_command_guard.py          │ ──► Denies rm -rf, drop table, format, forkbombs
│ ├─ turn1_enforced_gate_guard.py        │ ──► Denies tool execution before reading rules
│ ├─ burst_execution_guard.py            │ ──► Throttles heavy commands via CPU semaphore
│ └─ anti_sequential_guard.py            │ ──► Denies monolithic single-worker assignments
└────────────────────────────────────────┘
         │ (If Passed)
         ▼
[Tool Executed on Operating System]
         │
         ▼
┌────────────────────────────────────────┐
│ PostToolUse Hook Bus                   │
│ ├─ diff_security_inspector.py          │ ──► AST inspection for injected malicious syntax
│ ├─ secret_and_pii_scanner.py           │ ──► Masks keys, tokens, and personal credentials
│ ├─ anti_cheat_test_auditor.py          │ ──► Flags empty assertions and test mocks
│ └─ goal_drift_telemetry_tracker.py     │ ──► Measures progress against request contract
└────────────────────────────────────────┘
```

---

## 📊 Comparison Matrix

| Capability | Standard LLM / Vanilla Agent | Typical Multi-Agent Frameworks | Enterprise Agent Governance Framework (EAGF) |
|---|---|---|---|
| **Code Execution Boundary** | Unrestricted / Permissive | Basic prompt guardrails | **52 Physical OS-level Hooks (`HARD DENY`)** |
| **Orchestrator Role Discipline** | Often edits code directly | Role prompts without enforcement | **Strict No-Code Policy enforced at runtime** |
| **Concurrency Architecture** | Sequential single-thread | Unbounded parallel execution | **Asymmetric Dual-Pool (Cap 20 Cloud / Semaphore Local)** |
| **Hardware Adaptability** | None (causes system lockup) | Hardcoded thread limits | **Dynamic CPU & Memory Auto-Sensing (`psutil` 3-Zone)** |
| **File Collision Prevention** | File overwrites common | Lockfile conflicts | **Exclusive File Ownership Table (Pre-allocated)** |
| **Verification & Testing** | Self-checking (prone to bias) | Single pass test run | **ARCH-DOC-03 Decentralized Multi-Auditor Panel** |
| **Context Window Hygiene** | Context bloat & goal drift | Naive rolling truncation | **Pointer Dispatch + Structured 5-Part Handoffs** |
| **Turn 1 Compliance** | Not verified | Best-effort prompt ingestion | **Canary Token Proof-of-Reading Gate** |

---

## 🚀 Quick Start (5 Minutes)

### 1. Requirements
- Python 3.10+
- Dependencies: `psutil`, `pydantic`
```bash
pip install psutil pydantic
```

### 2. Integration into Runtime
Copy or symlink `enterprise_agent_governance/` into your agent runtime directory or workspace:
```bash
# Point runtime to hooks configuration
export AGENT_GOVERNANCE_HOOKS="./enterprise_agent_governance/hooks/hooks.json"
```

### 3. Verify System Health
Run the built-in self-test suite to validate hardware auto-sensing and hook integrity:
```bash
python enterprise_agent_governance/hook_utils/hardware_sensor.py
```

For complete integration instructions across Google Antigravity, Claude Code, Cursor, and custom CLI environments, see [QUICKSTART.md](QUICKSTART.md).

---

## 📚 Documentation Index

- 📘 **[ARCHITECTURE.md](ARCHITECTURE.md)** — In-depth architectural specification with 5 comprehensive Mermaid diagrams.
- 📂 **[DIRECTORY_GUIDE.md](DIRECTORY_GUIDE.md)** — Complete file-by-file blueprint and directory guide.
- ⚡ **[QUICKSTART.md](QUICKSTART.md)** — Step-by-step 5-minute setup and configuration manual.
- 🤖 **[README_AI.md](README_AI.md)** — System Prompt and Turn 1 Onboarding Guide tailored for AI Agents and LLMs.
- 🇻🇳 **[README_VN.md](README_VN.md)** — Bản tài liệu kiến trúc và hướng dẫn vận hành toàn diện bằng Tiếng Việt.
- 📜 **[LICENSE](LICENSE)** — Official MIT License (2026).

---

## 📄 License & Open Source Governance

Distributed under the **MIT License**. See [LICENSE](LICENSE) for complete terms.

Copyright (c) 2026 Enterprise Agent Governance Framework Contributors. Open for enterprise adoption, academic research, and community contributions.
