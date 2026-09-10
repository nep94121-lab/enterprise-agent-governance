# HANDOFF REPORT — [TASK_OR_MILESTONE_NAME]

> **Agent Identity:** [Agent Role / Name]<br>
> **Working Directory:** [Absolute Path to Agent Directory]<br>
> **Timestamp:** [YYYY-MM-DDTHH:MM:SSZ]<br>
> **Target Milestone:** [Milestone ID / Name]<br>
> **Handoff Type:** [Hard (Task complete) | Soft (Context transfer) | Partial (Stuck/Replaced)]

---

## 1. Observation (Empirical Findings)
*Document exact file paths, line numbers, verbatim tool outputs, test logs, and raw measurements. Quote directly without paraphrase.*

- **Inspected Files:**
  - `path/to/file.py:12-45`: [Verbatim code snippet or observation]
- **Command Execution Results:**
  ```text
  [Verbatim command output, exit codes, test counts]
  ```
- **Quantitative Metrics:**
  - Tests Passed: [N], Failed: [N], Skipped: [N]
  - Execution Time: [Seconds / ms]
  - Memory / Token Usage: [Units]

---

## 2. Logic Chain (Reasoning & Evidence Linkage)
*Provide step-by-step inductive/deductive reasoning linking every conclusion directly back to specific observations above.*

1. **Step 1 (Root Cause / Fact Correlation):**
   - Given Observation 1.X, [Logical step...]
2. **Step 2 (Architectural Rationale):**
   - Therefore, [Logical deduction...]
3. **Step 3 (Safety & Invariance):**
   - Confirming that [Invariance check...]

---

## 3. Caveats (Assumptions & Scope Boundaries)
*Explicitly record areas not investigated, environmental assumptions, edge cases deferred, and alternative interpretations evaluated.*

- **Assumptions:** [Assumptions regarding environment, tools, or dependencies]
- **Uninvestigated Areas:** [Boundaries outside current milestone scope]
- **Alternative Interpretations Considered:** [Options evaluated and discarded]
*(If none, state: "No caveats.")*

---

## 4. Conclusion (Actionable Assessment)
*Final assessment directly supported by the logic chain, actionable, unambiguous, and strictly scoped.*

- **Status:** [SUCCESS / BLOCKED / CONDITIONAL_PASS]
- **Deliverables Produced:**
  - `[path/to/created_or_modified_file]`: [Summary of changes]
- **Next Actions for Orchestrator / Downstream Agents:**
  - [Next actionable step 1]
  - [Next actionable step 2]

---

## 5. Verification Method (Independent Reproduction)
*Precise commands, test suites, and inspection steps for an independent auditor or Tech Lead to verify claims.*

### 5.1. Test & Build Commands
```powershell
# Command to execute tests
pytest tests/ -v -k "test_target_name"

# Command to check lint hygiene
ruff check path/to/target/
```

### 5.2. File Inspection Checklist
- [ ] Inspect `path/to/file` at line N to verify [Condition]
- [ ] Confirm zero occurrence of [Prohibited Pattern]

### 5.3. Invalidation Conditions
This report is rendered INVALID if any of the following occur:
1. Any test command in §5.1 returns a non-zero exit code.
2. A regression is detected in existing baseline tests.
3. [Specific condition invalidating the conclusion].
