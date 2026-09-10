#!/usr/bin/env python3
"""Enterprise Hook Utilities - Dynamic Workload Sensor.

Detects workload complexity dynamically across 3 dimensions:
1. Prompt structural parsing (bullets, phases, compound action clauses)
2. Workspace breadth sensing (scanning targeted directories for file count)
3. Target entity extraction (files, tables, functions, test cases)

Enforces the Atomic Workload Invariant:
  If Complexity(T) >= 2, spawned subagents must be >= Complexity(T).
  Eliminates role/name whitelists completely.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import logging
import os
import pathlib
import re
from typing import Any

from .config_loader import get_concurrency_rules

logger = logging.getLogger("enterprise_hooks.workload_sensor")

# Regex patterns for structural analysis
BULLET_LINE_REGEX = re.compile(r"^\s*(?:[-*•]|\d+[.)]|\([a-z0-9]+\))\s+(.+)$", re.MULTILINE)
PHASE_HEADER_REGEX = re.compile(
    r"(?i)\b(?:Bước|Phase|Giai đoạn|Task|Mục|TC|Step|Stage)\s*[-_:]?\s*\d+[:\s\-]*(.+?)(?=\n|$)",
    re.MULTILINE,
)

# Common file extensions for entity recognition
FILE_EXTENSION_REGEX = re.compile(
    r"[\w./\\-]+\.(?:py|json|md|ts|js|tsx|jsx|yaml|yml|sh|toml|sql|rs|go|html|css|env)\b",
    re.IGNORECASE,
)

# Test case and function identifiers
TEST_CASE_REGEX = re.compile(r"\b(?:TC|TEST)(?:-[A-Z0-9]+)*[-_]?\d+\b", re.IGNORECASE)
SYMBOL_REGEX = re.compile(r"\b(?:test_[a-zA-Z0-9_]+|[a-zA-Z0-9_]+_test)\b")

# Action clause triggers (Vietnamese & English technical action verbs)
ACTION_VERB_REGEX = re.compile(
    r"(?i)\b(?:kiểm tra|viết|sửa|test|audit|refactor|compile|build|tạo|xóa|review|benchmark|chạy|deploy|verify|scan|"
    r"implement|analyze|inspect|validate)\b"
)
CONJUNCTION_SPLIT_REGEX = re.compile(
    r"(?i)\b(?:đồng thời|và sau đó|tiếp theo|cùng với|song song với|and then|simultaneously|in parallel with|concurrently)\b|[;,]\s*(?=(?:kiểm tra|viết|sửa|test|audit|refactor|compile|build|tạo|xóa|review|benchmark|chạy|deploy|verify|scan)\b)"
)

# Path directory detection
DIR_MENTION_REGEX = re.compile(
    r"[\w./\\-]+[/\\](?:[*\w./\\-]+)?"
)


@dataclass
class ComplexityResult:
    """Detailed telemetry and assessment of workload complexity."""

    complexity_index: int = 1
    bullet_count: int = 0
    entity_count: int = 0
    workspace_file_count: int = 0
    action_clause_count: int = 0
    detected_bullets: list[str] = field(default_factory=list)
    detected_entities: list[str] = field(default_factory=list)
    detected_directories: list[str] = field(default_factory=list)
    detected_actions: list[str] = field(default_factory=list)
    spawned_subagents: int = 1
    threshold: int = 2
    is_violation: bool = False
    violation_details: str = ""
    rejection_contract: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)


class WorkloadSensor:
    """Dynamic workload sensor measuring task complexity across structural dimensions."""

    def __init__(self, atomic_threshold: int | None = None) -> None:
        rules = get_concurrency_rules()
        self.atomic_threshold: int = atomic_threshold or rules.get("atomic_workload_threshold", 2)

    def count_bullets(self, prompt: str) -> tuple[int, list[str]]:
        """Count structural bullets and phase headers in prompt."""
        if not prompt or not isinstance(prompt, str):
            return 0, []

        bullets: list[str] = []
        for match in BULLET_LINE_REGEX.finditer(prompt):
            line_content = match.group(1).strip()
            if len(line_content) > 3:
                bullets.append(line_content)

        for match in PHASE_HEADER_REGEX.finditer(prompt):
            phase_content = match.group(0).strip()
            if phase_content not in bullets:
                bullets.append(phase_content)

        return len(bullets), bullets

    def extract_entities(self, prompt: str) -> tuple[int, list[str]]:
        """Extract explicit targets: files, test cases, and code symbols."""
        if not prompt or not isinstance(prompt, str):
            return 0, []

        entities: set[str] = set()

        for match in FILE_EXTENSION_REGEX.finditer(prompt):
            path_str = match.group(0).strip("`'\" \t\r\n")
            if path_str and not path_str.startswith("http"):
                entities.add(path_str)

        for match in TEST_CASE_REGEX.finditer(prompt):
            entities.add(match.group(0).upper())

        for match in SYMBOL_REGEX.finditer(prompt):
            entities.add(match.group(0))

        entity_list = sorted(entities)
        return len(entity_list), entity_list

    def count_action_clauses(self, prompt: str) -> tuple[int, list[str]]:
        """Count distinct imperative technical action clauses in prompt."""
        if not prompt or not isinstance(prompt, str):
            return 0, []

        clauses: list[str] = []
        # Split on compound sentence conjunctions
        segments = CONJUNCTION_SPLIT_REGEX.split(prompt)
        for seg in segments:
            seg_clean = seg.strip()
            if len(seg_clean) > 8 and ACTION_VERB_REGEX.search(seg_clean):
                clauses.append(seg_clean[:80])

        return len(clauses), clauses

    def scan_workspace_breadth(
        self, prompt: str, workspace_root: pathlib.Path | str | None = None
    ) -> tuple[int, list[str], list[str]]:
        """Scan workspace directories mentioned in prompt and count targeted files."""
        if not prompt or not isinstance(prompt, str):
            return 0, [], []

        root = pathlib.Path(workspace_root).resolve() if workspace_root else pathlib.Path.cwd().resolve()
        detected_dirs: list[str] = []
        discovered_files: list[str] = []

        # Find potential directory mentions
        for match in DIR_MENTION_REGEX.finditer(prompt):
            candidate_raw = match.group(0).strip("`'\" \t\r\n.,:;")
            if not candidate_raw or candidate_raw.startswith("http"):
                continue

            candidate_path = pathlib.Path(candidate_raw)
            if not candidate_path.is_absolute():
                target_dir = root / candidate_path
            else:
                target_dir = candidate_path

            if target_dir.exists() and target_dir.is_dir():
                detected_dirs.append(str(target_dir))
                try:
                    # Scan source files up to 2 levels deep
                    for item in target_dir.glob("*"):
                        if item.is_file() and not item.name.startswith("."):
                            discovered_files.append(item.name)
                        elif item.is_dir() and not item.name.startswith((".", "__")):
                            for sub_item in item.glob("*"):
                                if sub_item.is_file() and not sub_item.name.startswith("."):
                                    discovered_files.append(f"{item.name}/{sub_item.name}")
                except OSError as err:
                    logger.debug("Error scanning directory %s: %s", target_dir, err)

        unique_files = sorted(set(discovered_files))
        return len(unique_files), detected_dirs, unique_files

    def assess_complexity(
        self,
        prompt: str,
        spawned_subagents: int = 1,
        workspace_root: pathlib.Path | str | None = None,
    ) -> ComplexityResult:
        """Evaluate prompt and calculate workload complexity index C(T).

        Applies formula:
          C(T) = max(bullet_count, entity_count, workspace_file_count, action_clause_count, 1)
        """
        bullet_count, bullets = self.count_bullets(prompt)
        entity_count, entities = self.extract_entities(prompt)
        action_count, actions = self.count_action_clauses(prompt)
        file_count, dirs, _ = self.scan_workspace_breadth(prompt, workspace_root)

        # Composite complexity is the maximum atomic workload dimension
        complexity_index = max(bullet_count, entity_count, file_count, action_count, 1)

        is_violation = False
        violation_details = ""
        rejection_contract: dict[str, Any] | None = None

        if complexity_index >= self.atomic_threshold and spawned_subagents < complexity_index:
            is_violation = True
            if file_count >= complexity_index and dirs:
                violation_details = (
                    f"Phát hiện {file_count} tệp độc lập trong thư mục đích ({', '.join(dirs[:2])}) "
                    f"nhưng chỉ gọi {spawned_subagents} Subagent ôm đồm đơn lẻ."
                )
            elif bullet_count >= complexity_index:
                violation_details = (
                    f"Phát hiện {bullet_count} nhiệm vụ/bước độc lập trong prompt "
                    f"nhưng chỉ gọi {spawned_subagents} Subagent ôm đồm đơn lẻ."
                )
            elif entity_count >= complexity_index:
                violation_details = (
                    f"Phát hiện {entity_count} thực thể/tệp mục tiêu độc lập "
                    f"nhưng chỉ gọi {spawned_subagents} Subagent ôm đồm đơn lẻ."
                )
            else:
                violation_details = (
                    f"Phát hiện {complexity_index} đơn vị tải trọng phức tạp "
                    f"nhưng chỉ gọi {spawned_subagents} Subagent ôm đồm đơn lẻ."
                )

            rejection_contract = {
                "allow": False,
                "error_code": "ATOMIC_WORKLOAD_VIOLATION",
                "reason": "LÃNG PHÍ CPU VÀ LÀM CHẬM TIẾN ĐỘ THEO TRIẾT LÝ CỦA SẾP!",
                "telemetry": {
                    "detected_complexity": complexity_index,
                    "spawned_subagents": spawned_subagents,
                    "violation_details": violation_details,
                },
                "action_required": (
                    f"Yêu cầu băm nhỏ công việc thành tối thiểu {complexity_index} Subagents "
                    f"chạy song song đồng thời trên Bể 1 ngay lập tức!"
                ),
            }

        return ComplexityResult(
            complexity_index=complexity_index,
            bullet_count=bullet_count,
            entity_count=entity_count,
            workspace_file_count=file_count,
            action_clause_count=action_count,
            detected_bullets=bullets,
            detected_entities=entities,
            detected_directories=dirs,
            detected_actions=actions,
            spawned_subagents=spawned_subagents,
            threshold=self.atomic_threshold,
            is_violation=is_violation,
            violation_details=violation_details,
            rejection_contract=rejection_contract,
        )


def assess_workload(
    prompt: str,
    spawned_subagents: int = 1,
    workspace_root: pathlib.Path | str | None = None,
    threshold: int | None = None,
) -> ComplexityResult:
    """Convenience helper to assess workload complexity."""
    sensor = WorkloadSensor(atomic_threshold=threshold)
    return sensor.assess_complexity(
        prompt=prompt,
        spawned_subagents=spawned_subagents,
        workspace_root=workspace_root,
    )
