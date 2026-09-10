# GATE STATUS — [PROJECT_NAME]

> **Project ID:** [PROJ_ID]<br>
> **Last Updated:** [YYYY-MM-DDTHH:MM:SSZ]<br>
> **Orchestrator:** [PM_ORCHESTRATOR_ID]<br>
> **Overall Status:** [IN_PROGRESS | COMPLETED | BLOCKED]

---

## 1. 7 Phase Gates Lifecycle Board

| Phase | Phase Name | Primary Agent | Status | Gate Exit Criteria | Approval Sign-off | Completion Timestamp |
|:---:|---|---|:---:|---|:---:|:---:|
| **1** | **Discovery** | PM Orchestrator | PENDING | User intent fully clarified, acceptance criteria established, zero assumptions. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **2** | **Exploration** | Explorers (2–3 parallel) | PENDING | Complete survey of code, tests, and dependencies. 0 destructive operations. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **3** | **Questions & Edge Cases** | PM / Lead Architect | PENDING | All ambiguities resolved, adversarial edge cases identified, DoD locked. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **4** | **Architecture Design** | PM Orchestrator | PENDING | Implementation plan authored, milestones defined with explicit ownership. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **5** | **Implementation** | Specialized Workers | PENDING | Minimal changes, 0 regressions, unit tests co-located, 0 hardcoded cheats. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **6** | **Quality Review & Challenger** | QA Challenger & Auditor | PENDING | Confidence Scoring >= 80 enforced, 10-Tier Tech Lead Pre-Flight passed. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |
| **7** | **Summary & Handoff** | PM Orchestrator | PENDING | Comprehensive audit report delivered, zero workspace pollution, zombies cleaned. | [Sign-off] | [YYYY-MM-DDTHH:MM:SSZ] |

---

## 2. Gate Decision Log & Blocker Register

| Gate | Timestamp | Decision | Reason / Evidence | Remediation Required |
|:---:|:---:|:---:|---|---|
| Gate 1 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from requirements review] | [N/A or required fixes] |
| Gate 2 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from explorer handoffs] | [N/A or required fixes] |
| Gate 3 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from edge case analysis] | [N/A or required fixes] |
| Gate 4 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from design review] | [N/A or required fixes] |
| Gate 5 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from worker test suites] | [N/A or required fixes] |
| Gate 6 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from adversarial audit] | [N/A or required fixes] |
| Gate 7 | [Timestamp] | [PASSED / BLOCKED] | [Evidence from final verification] | [N/A or required fixes] |

---

## 3. Subagent Resource & Budget Tracking

- **Active Subagents:** [N / Max 5 concurrent]
- **Timer Discipline:** 1m (small tasks) | 2m (medium tasks) | 3m (large tasks)
- **Token Budget Utilization:**
  - `pm_orchestrator`: [Current Tokens] / 12,000 max
  - `backend_developer`: [Current Tokens] / 12,000 max
  - `frontend_developer`: [Current Tokens] / 12,000 max
  - `devops_security`: [Current Tokens] / 12,000 max
  - `qa_challenger`: [Current Tokens] / 12,000 max
  - `tech_lead_auditor`: [Current Tokens] / 12,000 max
