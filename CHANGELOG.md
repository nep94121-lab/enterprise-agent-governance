# 📋 CHANGELOG — Enterprise Agent Governance Framework (EAGF)

All notable changes to the Enterprise Agent Governance Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
