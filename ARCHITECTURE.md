# 🏛️ Enterprise Agent Governance Framework — Architecture Specification (ARCHITECTURE.md)

> **In-Depth Technical Architecture, Asymmetric Dual-Pool Concurrency, Physical Runtime Interception & Multi-Auditor Governance.**

[![Architecture Version](https://img.shields.io/badge/Architecture-Enterprise%20v3.8-blueviolet.svg)](#)
[![Status](https://img.shields.io/badge/Status-Officially%20Ratified-brightgreen.svg)](#)
[![Standard](https://img.shields.io/badge/Standard-ARCH--DOC--03%20Compliance-blue.svg)](#)

---

## 📑 Architectural Table of Contents

1. [Architectural Axioms & Design Principles](#1-architectural-axioms--design-principles)
2. [Sơ Đồ 1: 3-Tier Multi-Agent Hierarchy Architecture](#2-sơ-đồ-1-3-tier-multi-agent-hierarchy-architecture)
3. [Sơ Đồ 2: Asymmetric Dual-Pool Concurrency & Dynamic CPU Governor](#3-sơ-đồ-2-asymmetric-dual-pool-concurrency--dynamic-cpu-governor)
4. [Sơ Đồ 3: The 7-Phase Sequential Workflow & State Machine](#4-sơ-đồ-3-the-7-phase-sequential-workflow--state-machine)
5. [Sơ Đồ 4: Physical Hook Interception Engine Lifecycle](#5-sơ-đồ-4-physical-hook-interception-engine-lifecycle)
6. [Sơ Đồ 5: ARCH-DOC-03 Multi-Auditor Panel Protocol](#6-sơ-đồ-5-arch-doc-03-multi-auditor-panel-protocol)
7. [Dynamic Hardware Auto-Sensing Engine](#7-dynamic-hardware-auto-sensing-engine)
8. [Blast Radius Isolation & Exclusive File Ownership](#8-blast-radius-isolation--exclusive-file-ownership)
9. [Context Window Hygiene & Laconic Pointer Dispatch](#9-context-window-hygiene--laconic-pointer-dispatch)

---

## 1. Architectural Axioms & Design Principles

The **Enterprise Agent Governance Framework (EAGF)** is built upon four foundational axioms designed to eliminate the inherent unreliability, race conditions, and uncontrolled resource consumption of autonomous AI agent networks:

1. **Zero-Trust Physical Enforcement:** Software safety cannot rely on prompt instructions, system rules text, or LLM self-restraint. All tool invocations (`run_command`, `write_to_file`, `replace_file_content`, `invoke_subagent`) must pass through an out-of-process, deterministic runtime hook interceptor that executes at the operating system layer.
2. **Strict No-Code Boundary for Orchestrators:** Orchestrator agents (Tier 1 Executive Agent and Tier 2 Project Managers) must never touch source code. They ingest stakeholder intent, establish scope contracts, allocate files, and schedule specialized workers.
3. **Decoupled Compute Environments (Asymmetric Dual-Pool):** High-concurrency cloud reasoning (LLM API calls) and heavy local compute (compiling, testing, container builds) have fundamentally different resource profiles. Cloud thinking can scale up to 20 parallel workers, while local burst compute must be throttled dynamically to the physical hardware profile.
4. **Decentralized Multi-Auditor Panel (ARCH-DOC-03):** Single-auditor verification is inherently vulnerable to bias and false positives. High-assurance deliverables require a consensus panel consisting of independent Explorer, Reviewer, Challenger, and Auditor agents achieving $\ge 90.0/100$ consensus with zero blocking issues.

---

## 2. Sơ Đồ 1: 3-Tier Multi-Agent Hierarchy Architecture

The organizational structure separates governance, coordination, and technical execution into 3 immutable tiers backed by a foundation of physical runtime hooks:

```mermaid
graph TD
    classDef t0 fill:#1e1b4b,stroke:#6366f1,stroke-width:2px,color:#fff;
    classDef t1 fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef t2 fill:#7c2d12,stroke:#f97316,stroke-width:2px,color:#fff;
    classDef t3 fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;

    subgraph Tier0 ["🛡️ TIER 0: CONSTITUTIONAL & PHYSICAL RUNTIME LAYER"]
        H1["52 Physical Interceptor Hooks (hooks.json)"]
        H2["Dynamic Hardware Auto-Sensing Engine"]
        H3["Audit & Telemetry Log (trajectory.db / transcript.jsonl)"]
    end

    subgraph Tier1 ["👑 TIER 1: EXECUTIVE AGENT (USER-FACING ORCHESTRATOR)"]
        TopAgent["Top-Level Agent\n- Direct Human Dialogue\n- Intent Decomposition\n- Compiles request_artifact.md\n- NO-CODE INVARIANT (Hard Deny)"]
    end

    subgraph Tier2 ["📋 TIER 2: LEAD PROJECT MANAGERS (PM ORCHESTRATORS)"]
        PM1["Lead PM Orchestrator\n- 7 Phase Gates State Machine\n- Exclusive File Ownership Allocation\n- Staggered Rolling Batches Scheduling\n- Context Successor Chaining (Handoff)"]
    end

    subgraph Tier3 ["⚙️ TIER 3: SPECIALIZED TECHNICAL WORKERS (14 ROLES)"]
        subgraph GroupA ["Core Engineering"]
            W_BE["Backend Developer"]
            W_FE["Frontend Developer"]
            W_DB["Data & ML Engineer"]
            W_MB["Mobile Developer"]
        end
        subgraph GroupB ["Defense & Infrastructure"]
            W_SEC["AppSec Sentinel"]
            W_OPS["DevOps & Security"]
            W_SAGA["State Checkpoint Curator"]
        end
        subgraph GroupC ["Audit & Telemetry Panel"]
            W_EXP["Codebase Explorer (Read-Only)"]
            W_QA["QA Challenger (Fuzzing / Anti-Cheat)"]
            W_TL["Tech Lead Auditor (10-Layer Pre-Flight)"]
            W_WD["Watchdog Inspector (Telemetry / Anti-Loop)"]
        end
    end

    Human["👤 Human Stakeholder / User"] <==> TopAgent
    TopAgent ==>|Task Contract / DISPATCH| PM1
    PM1 ==>|Rolling Batch 1 <= 20| GroupA
    PM1 ==>|Rolling Batch 2 <= 20| GroupB
    PM1 ==>|Rolling Batch 3 <= 20| GroupC

    Tier0 -.->|Physical Pre/Post Enforcement| TopAgent
    Tier0 -.->|Physical Pre/Post Enforcement| PM1
    Tier0 -.->|Physical Pre/Post Enforcement| Tier3

    class H1,H2,H3 t0;
    class TopAgent t1;
    class PM1 t2;
    class W_BE,W_FE,W_DB,W_MB,W_SEC,W_OPS,W_SAGA,W_EXP,W_QA,W_TL,W_WD t3;
```

---

## 3. Sơ Đồ 2: Asymmetric Dual-Pool Concurrency & Dynamic CPU Governor

Traditional AI workflows either bottleneck on sequential execution or spawn unlimited subagents that overwhelm host CPU resources. EAGF divides execution into two isolated pools:

```mermaid
flowchart TD
    TaskIn["🚀 High-Volume Task Workloads (N Tasks)"] --> Router{"Workload Classifier\n(Dynamic Sensing)"}

    subgraph Pool1 ["🌐 POOL 1: CLOUD THINKING & TOOL I/O"]
        direction TB
        P1_Desk["Cloud Reasoning & Light File I/O\n(LLM Inference, Search, AST Analysis)"]
        P1_Cap["Concurrency Cap: 20 Parallel Subagents\n(Kubernetes parallelism: 20 standard)"]
        P1_Chunks["Rolling Batch Chunks\nBatch 1 (20) ──► Batch 2 (20) ──► Batch 3 (N)"]
        P1_Desk --> P1_Cap --> P1_Chunks
    end

    subgraph Pool2 ["💻 POOL 2: LOCAL BURST COMPUTE SEMAPHORE"]
        direction TB
        P2_Cmd["Heavy Local Commands\n(pytest, cargo build, npm test, docker)"]
        P2_Queue["FIFO Micro-Queue Semaphore\n(Slots dynamically scaled to physical cores)"]
        P2_Gov["psutil 3-Zone Dynamic CPU Governor"]
        P2_Cmd --> P2_Queue --> P2_Gov
    end

    subgraph Zones ["Dynamic 3-Zone CPU Governor"]
        Z1["🟢 Acceleration Zone (< 60% CPU)\nInstant slot release from queue\n(Maximum compute throughput)"]
        Z2["🟡 Golden Zone (60% - 85% CPU)\nSteady-state execution\n(100% capacity without throttling)"]
        Z3["🔴 Thermal Protection Zone (> 85% CPU)\nStaggered 1.0s wait intervals\n(Prevents fan scream and OS freeze)"]
    end

    Router -- "Cloud Inference / Light Tool I/O" --> Pool1
    Router -- "Heavy Terminal Execution" --> Pool2
    P2_Gov --> Zones
    Zones --> Exec["Local OS Process Execution\n(180s Zombie Task Auto-Kill)"]
```

---

## 4. Sơ Đồ 3: The 7-Phase Sequential Workflow & State Machine

EAGF organizes project lifecycle into a strict finite-state machine. A phase cannot be marked complete until all phase gate invariants are satisfied and verified on disk:

```mermaid
stateDiagram-v2
    [*] --> Phase1_ContractIngestion: Task Received from Human

    Phase1_ContractIngestion --> Phase2_CodebaseExploration: request_artifact.md created on disk
    note right of Phase1_ContractIngestion
        Invariant: Fixed requirement contract.
        Scoping category and DoD established.
    end note

    Phase2_CodebaseExploration --> Phase3_ArchitectureBlueprint: codebase_map.md compiled
    note right of Phase2_CodebaseExploration
        Invariant: 100% Read-Only exploration.
        Zero source file modifications permitted.
    end note

    Phase3_ArchitectureBlueprint --> Phase4_ExclusiveFileOwnership: Blueprint ratified by Tech Lead
    note right of Phase3_ArchitectureBlueprint
        Invariant: Architectural pattern selected.
        ADR alignment verified.
    end note

    Phase4_ExclusiveFileOwnership --> Phase5_ImplementationRolling: Ownership Table in progress.md
    note right of Phase4_ExclusiveFileOwnership
        Invariant: 1-to-1 File-to-Worker mapping.
        Zero overlapping edit paths.
    end note

    Phase5_ImplementationRolling --> Phase6_MultiAuditorVerification: All worker handoffs received
    note right of Phase5_ImplementationRolling
        Invariant: Dual-Pool rolling batches (<=20).
        Staggered burst local queue.
    end note

    Phase6_MultiAuditorVerification --> Phase7_CleanHandoff: Consensus score >= 90.0 / 100
    Phase6_MultiAuditorVerification --> Phase5_ImplementationRolling: Blocking issues detected (Remediation loop)
    note right of Phase6_MultiAuditorVerification
        Invariant: 4-Layer multi-perspective audit.
        Zero mock cheat test facades.
    end note

    Phase7_CleanHandoff --> [*]: Master handoff.md & Teardown complete
    note right of Phase7_CleanHandoff
        Invariant: All background tasks terminated.
        Zero orphan zombie processes.
    end note
```

---

## 5. Sơ Đồ 4: Physical Hook Interception Engine Lifecycle

Physical hooks intercept agent tool calls in real time. If any invariant is violated, the hook returns non-zero exit codes to block execution:

```mermaid
sequenceDiagram
    autonumber
    actor LLM as Agent / Subagent LLM
    participant Bus as Hook Event Bus
    participant SecHooks as Security & Boundary Guards
    participant ConcurHooks as Concurrency & CPU Governor
    participant OS as Operating System / File System
    participant AuditHooks as Post-Execution Audit & Telemetry

    LLM->>Bus: Tool Call Proposed (e.g. run_command, write_to_file)
    
    rect rgb(240, 245, 255)
        note over Bus,SecHooks: PRE-TOOL HOOKS (P0 Priority)
        Bus->>SecHooks: Validate Scope, Command Safety, Turn-1 Canary
        alt Rule Violated (e.g., Unassigned file, Dangerous command)
            SecHooks-->>LLM: 🚨 HARD DENY (Tool Blocked, Reason Logged)
        else Validation Passed
            SecHooks-->>Bus: ALLOW
        end
    end

    rect rgb(255, 250, 240)
        note over Bus,ConcurHooks: CONCURRENCY HOOKS (P1 Priority)
        Bus->>ConcurHooks: Check CPU Load & Request Queue Slot
        ConcurHooks->>ConcurHooks: Apply psutil 3-Zone Governor
        ConcurHooks-->>Bus: Slot Acquired
    end

    Bus->>OS: Forward Tool Call to OS / Disk
    OS-->>Bus: Tool Return Output / Exit Code

    rect rgb(240, 255, 245)
        note over Bus,AuditHooks: POST-TOOL HOOKS (P2 Priority)
        Bus->>AuditHooks: Diff Analysis, Secret/PII Masking, Anti-Cheat Check
        AuditHooks->>AuditHooks: Record Metrics in trajectory.db
        AuditHooks-->>LLM: Sanitized Output & Execution Telemetry
    end
```

---

## 6. Sơ Đồ 5: ARCH-DOC-03 Multi-Auditor Panel Protocol

Single-agent verification produces confirmation bias. Phase 6 enforces the **ARCH-DOC-03 Decentralized Multi-Auditor Panel**:

```mermaid
graph TD
    classDef panel fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef score fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef reject fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;

    Deliverable["📦 Phase 5 Engineering Deliverable"] --> Panel["🏛️ ARCH-DOC-03 Audit Council"]

    subgraph PanelMembers ["Independent Audit Perspectives"]
        A1["🔍 Codebase Explorer\n(Structural Integrity & Import Graphs)"]
        A2["🛡️ AppSec Sentinel\n(Vulnerability Scan & Secret Hygiene)"]
        A3["⚡ QA Challenger\n(Adversarial Fuzzing & Anti-Cheat Audit)"]
        A4["📐 Tech Lead Auditor\n(10-Layer Pre-Flight & Architecture Alignment)"]
    end

    Panel --> PanelMembers

    A1 --> S1["Score 1 (0-100)"]
    A2 --> S2["Score 2 (0-100)"]
    A3 --> S3["Score 3 (0-100)"]
    A4 --> S4["Score 4 (0-100)"]

    S1 & S2 & S3 & S4 --> Synthesizer["⚖️ Consensus Synthesis Engine"]

    Synthesizer --> Decision{"Evaluation Criteria:\n1. Mean Score >= 90.0/100\n2. Blocking Issues == 0"}

    Decision -- "PASSED" --> Approved["✅ Phase 7 Gate Authorization"]
    Decision -- "FAILED" --> Rejected["❌ Remediation Loop to Phase 5"]

    class Panel panel;
    class Approved score;
    class Rejected reject;
```

---

## 7. Dynamic Hardware Auto-Sensing Engine

Rather than relying on hardcoded concurrency limits, EAGF's `hardware_sensor.py` dynamically queries the host environment using operating system APIs and the `psutil` library:

```python
# Conceptual Auto-Sensing Logic
def determine_execution_capacity():
    physical_cores = psutil.cpu_count(logical=False) or 2
    total_ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    
    # Scale local compute slots proportionally
    if physical_cores <= 4:
        local_burst_slots = max(2, physical_cores - 1)
    elif physical_cores <= 16:
        local_burst_slots = int(physical_cores * 0.75)
    else:
        local_burst_slots = min(48, int(physical_cores * 0.5))
        
    return {
        "cloud_concurrency_cap": 20,
        "local_burst_slots": local_burst_slots,
        "ram_reserve_gb": max(2.0, total_ram_gb * 0.15)
    }
```

### Elastic Hardware Profile Support:
- **Low-Power Laptops (2 Cores / 4-8 GB RAM):** Automatically scales local burst slots to 2, increases thermal pause intervals to 2.0s, and maintains fluid host responsiveness.
- **Developer Workstations (4-8 Cores / 16-32 GB RAM):** Allocates 3–6 local burst slots, maintaining peak CPU utilization between 60% and 85%.
- **Enterprise Build Servers (16-128 Cores / 64-512 GB RAM):** Scales up to 24–48 simultaneous local processes with massive compilation throughput.

---

## 8. Blast Radius Isolation & Exclusive File Ownership

EAGF enforces **Zero Overlapping File Ownership**:
1. In Phase 4, the PM Orchestrator partitions all project files among active workers.
2. The assignment is published in `progress.md` before any worker is spawned.
3. The hook `scope_boundary_enforcer.py` intercepts every `write_to_file` and `replace_file_content` call. If an agent attempts to write to a path outside its registered scope, the operation is blocked with `ERR_OUT_OF_SCOPE_MODIFICATION`.
4. This completely eliminates file write collisions, merge conflicts, and unintentional state regressions.

---

## 9. Context Window Hygiene & Laconic Pointer Dispatch

Context window saturation causes catastrophic degradation in LLM reasoning capabilities. EAGF enforces two strict hygiene invariants:

### 1. Laconic Pointer Dispatch
PMs do not inject code files or lengthy specifications into the `invoke_subagent` prompt. Instead:
- PM writes `DISPATCH.md` (Contract) and `BRIEFING.md` (Context) directly to `.agents/[worker_id]/`.
- The prompt sent to the subagent is a compact pointer ($\le 20$ lines) instructing the subagent to load its instructions from disk.

### 2. Successor Chaining (Handoff Invariant)
When a PM Orchestrator approaches context saturation ($\ge 40$ tool calls):
- The PM compiles a complete, self-contained state checkpoint: `handoff.md`.
- The PM spawns a successor PM, passing only a pointer to `handoff.md`.
- The predecessor PM terminates gracefully, resetting context to 0% bloat while preserving 100% of project momentum.
