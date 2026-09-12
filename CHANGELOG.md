# 📋 CHANGELOG — Enterprise Agent Governance Framework (EAGF)

All notable changes to the Enterprise Agent Governance Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-09-12

### ⚡ Programming Safety Relays & Circuit Breakers (Zero-Crash Assurance)
- **Runtime Safety Relays Framework (`hook_utils/safety_relays.py`):** Added production circuit breakers for recursive infinite loops (`LoopBreaker`), memory spike trips >500MB (`MemorySpikeBreaker`), error cascading $\ge 3$ iterations (`CascadeBreaker`), scope boundary enforcement (`ScopeBreaker`), and file lock timeout breakers (`LockTimeoutBreaker`).
- **Physical Safety Guard Hook (`hooks_scripts/programming_safety_relay_guard.py`):** Intercepts tool execution to trip relays and transition systems into a deterministic Safe Mode within $\le 100$ms upon detecting abnormal programming anomalies.
- **Specification Authority (`rules_shared/PROGRAMMING_SAFETY_RELAYS_SPEC.md`):** Established comprehensive architectural standards for programming circuit breakers and graceful recovery states.

### ⚔️ Adversarial Attack Testing Engine (Stress & Fuzzing Resilience)
- **Adversarial Interception Hook (`hooks_scripts/adversarial_attack_testing_hook.py`):** Real-time interception against 4 major threat vectors: SQLi/Malformed payloads, OS command injection, context/prompt injection, and path traversal bypasses.
- **Automated Adversarial Test Suite (`tests/test_adversarial_safety_relays.py`):** Passed 100% (5/5) across all attack vectors with zero fake assertions or empty mocks.
- **Adversarial Standards Specification (`rules_shared/ADVERSARIAL_ATTACK_TESTING_SPEC.md`):** Complete red-team validation playbook and fuzzing rules.

### 👑 Enterprise /leadpm Scale Invariant: Minimum 100 Cumulative Agents
- **Minimum Subagent Scale Invariant Enforcer (`hooks_scripts/lead_pm_minimum_agent_enforcer.py`):** Enforces that any enterprise `/leadpm` command must mobilize **$\ge 100$ cumulative subagents** across its multi-wave lifecycle. Blocks early task closure or Gate 6.5 completion with a `HARD DENY` if total spawned agents $< 100$.
- **Dual-Pool Rolling Waves Compatibility:** Maintains strict $\le 20$ active subagent concurrency (Pool 1) on workstation hardware (4C/8T) while enabling deep hierarchical task decomposition across consecutive waves (achieving 160+ cumulative subagents in live tests).
- **Rulebook Synchronization:** Updated `AGENTS.md`, `AGENTS_SYSTEM_DESIGN.md`, and `LEAD_PM_RULES_INDEX.md` to reflect the 100-agent scale invariant.

---

## [2.0.0] - 2026-09-12

### 🛡️ Security Hardening & Anti-Bypass (242+ Vulnerabilities Patched)
- **Fail-Closed Runtime Architecture:** Converted all 60+ physical runtime hooks from fail-open to fail-closed. Any AST parsing error, schema validation fault, or unexpected runtime exception now safely triggers an explicit `HARD DENY` (`sys.exit(1)`), eliminating silent bypasses.
- **Starvation Deadlock Elimination:** Patched distributed multi-agent file locking on Windows NTFS (`os.O_CREAT | os.O_EXCL` with exponential backoff and jitter), preventing concurrent subagents from deadlocking on shared quota states.
- **OOM & Large Payload Defense:** Hardened standard input handlers (`common_hook_lib.read_stdin_payload`) with strict 10MB chunked streaming and byte-length guards, neutralizing denial-of-service via massive tool outputs.
- **Zombie Process Recovery:** Implemented automated lifecycle garbage collection for orphan subagent processes and stranded background threads with strict 180s liveness timers.
- **Split-Brain State Synchronization:** Built atomic commit transactions for `.system_state/concurrency_quota.json`, preventing race conditions across multi-PM swarms.
- **Adversarial Red Team Verification:** Ran comprehensive adversarial stress tests across 5 major threat vectors; passed with 100% defect remediation and zero regressions.

### ⚡ Lean Context & Anti-Truncation Architecture (74% ➔ 0% Truncation)
- **Top-Level `AGENTS.md` Slimming:** Refactored core executive rules from **92.7 KB down to 19.05 KB** (-79.5% reduction). Eliminates the 74.1% context truncation bug where LLM agents lost critical governance instructions after line 205.
- **Modular Architecture Decoupling:** Separated advanced meta-governance patterns (Non-blocking 60s escalation, Dual-mode swarm, 6 Specialized PM matrix) into a dedicated [`AGENTS_SYSTEM_DESIGN.md`](rules/AGENTS_SYSTEM_DESIGN.md) (14.78 KB), ensuring single-view completeness without tool buffer overflow.
- **SSOT Rules Consolidation (`rules_shared/`):** Purged **54 duplicate spec files** (`MODULAR_FRAMEWORK_RULES.md`, `OWASP_LLM_COMPLIANCE_SPEC.md`, `TAU_BENCH_COMPLIANCE_SPEC.md`, `SUPPLY_CHAIN_DEPENDENCY_PINNING.md`, `SWE_BENCH_REPRODUCTION_PROTOCOL.md`) scattered across 14 role folders. Centralized into a single authoritative source of truth under `rules/rules_by_role/rules_shared/`, reclaiming **912.7 KB** of repository bloat.
- **Lead PM Context Relief:** Introduced [`LEAD_PM_RULES_INDEX.md`](rules/rules_by_role/lead_pm/LEAD_PM_RULES_INDEX.md) (13.5 KB) replacing the bloated 134 KB rulebook at Turn 1, reducing initial token payload by **89.9%** (~70,000 tokens saved) and preventing self-succession context overload.

### 🔒 Privacy Shield & Secret Sanitization
- **100% Zero-Leak Open-Source Audit:** Scrubbed all private IP addresses, personal email addresses, local workstation names, and private SSH key filenames across all repository rules, test fixtures, and documentation into generic, secure placeholders (`100.x.x.x`, `user@example.com`, `WORKSTATION-MAIN`, `id_rsa`).
- **Dynamic Path Detection:** Replaced hardcoded administrative filesystem paths in `grill_me_research_enforcer.py` with dynamic `Path.home()` and workspace detection.

---

## [1.0.0] - 2026-09-10

### 🚀 Initial Open Source Release
- **Core Architecture:** 3-Tier Hierarchical Governance Model (Tier 1 Executive $\to$ Tier 1.5 Meta-Panel $\to$ Tier 2 Multi-PM Swarm $\to$ Tier 3 Technical Workers).
- **Physical Runtime Interception:** 51 OS-level PreToolUse and PostToolUse hook interceptors.
- **Dual-Pool Asymmetric Concurrency:** Unlimited cloud reasoning capped at 20 parallel subagents (Pool 1) coupled with local hardware burst regulation via a 3-4 slot dynamic semaphore (Pool 2).
- **Hardware-Aware CPU Governor:** 3-Zone `psutil` real-time CPU monitor (Accelerate <60%, Golden 60-85%, Thermal Guard >85%).
- **Interactive Verification:** 1-Click live benchmark suite (`test_live.py`) demonstrating empirical superiority over unconstrained vanilla agents across 7 operational vectors.
- **14 Specialized Discipline Roles:** Comprehensive governance rulesets for Frontend, Backend, DevOps, QA, Security Sentinel, Watchdog, Tech Lead, and PM roles.
- **Bilingual Documentation:** Full English (`README.md`) and Vietnamese (`README_VN.md`) documentation suites.
