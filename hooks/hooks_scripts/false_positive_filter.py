"""
False Positive Filter for Code Analysis Hooks

Filters false positives from code analysis tools by leveraging:
- Known safe patterns whitelist
- Context-aware filtering
- Pattern intersection with diffs
- Learning from corrections

Usage:
    from hooks_scripts.false_positive_filter import FalsePositiveFilter

    filter = FalsePositiveFilter()
    filtered_results = filter.filter_results(raw_results, diff_content)
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


def _paths_match(p1: str, p2: str) -> bool:
    """So sánh đường dẫn an toàn đa nền tảng (Windows/POSIX, tuyệt đối/tương đối, hoa/thường)."""
    if not p1 or not p2:
        return False
    n1 = p1.replace("\\", "/").strip().rstrip("/").lower()
    n2 = p2.replace("\\", "/").strip().rstrip("/").lower()

    # Strip git diff prefixes a/ and b/ if present
    s1 = n1[2:] if (n1.startswith("a/") or n1.startswith("b/")) else n1
    s2 = n2[2:] if (n2.startswith("a/") or n2.startswith("b/")) else n2

    for a, b in ((n1, n2), (s1, s2), (n1, s2), (s1, n2)):
        if a == b:
            return True
        if a.endswith("/" + b) or b.endswith("/" + a):
            return True
        if "/" not in a and b.endswith("/" + a):
            return True
        if "/" not in b and a.endswith("/" + b):
            return True
    return False

@dataclass
class Finding:
    """Represents a single finding from a code analysis tool."""
    tool: str
    rule_id: str
    file_path: str
    line_number: int
    message: str
    severity: str = "unknown"
    code_snippet: str = ""
    diff_context: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "severity": self.severity,
            "code_snippet": self.code_snippet,
            "diff_context": self.diff_context,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            tool=data.get("tool") or "",
            rule_id=data.get("rule_id") or "",
            file_path=data.get("file_path") or "",
            line_number=data.get("line_number") or 0,
            message=data.get("message") or "",
            severity=data.get("severity") or "unknown",
            code_snippet=data.get("code_snippet") or "",
            diff_context=data.get("diff_context") or "",
        )

    @property
    def signature(self) -> str:
        """Generate unique signature for this finding."""
        norm_path = self.file_path.replace("\\", "/").lower() if self.file_path else ""
        content = f"{self.tool}:{self.rule_id}:{norm_path}:{self.line_number}:{self.message or ''}"
        return hashlib.md5(content.encode()).hexdigest()


@dataclass
class WhitelistEntry:
    """An entry in the safe patterns whitelist."""
    pattern: str
    pattern_type: str  # "regex", "exact", "contains", "rule_id"
    reason: str = ""
    added_date: str = field(default_factory=lambda: datetime.now().isoformat())
    author: str = ""
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    match_count: int = 0
    false_positive_count: int = 0

    def matches(self, finding: Finding) -> bool:
        """Check if this whitelist entry matches the given finding."""
        if self.file_path:
            if not _paths_match(self.file_path, finding.file_path):
                return False

        if self.line_start and finding.line_number < self.line_start:
            return False
        if self.line_end and finding.line_number > self.line_end:
            return False

        if self.pattern_type == "rule_id":
            return self.pattern in finding.rule_id or finding.rule_id in self.pattern

        if self.pattern_type == "exact":
            return self.pattern == finding.message or self.pattern == finding.code_snippet

        if self.pattern_type == "contains":
            return self.pattern.lower() in finding.message.lower() or \
                   self.pattern.lower() in finding.code_snippet.lower()

        if self.pattern_type == "regex":
            try:
                return bool(re.search(self.pattern, finding.message, re.IGNORECASE)) or \
                       bool(re.search(self.pattern, finding.code_snippet, re.IGNORECASE))
            except re.error:
                return False

        return False


@dataclass
class ContextPattern:
    """A pattern that is safe only in specific contexts."""
    pattern: str
    context_keywords: list[str]  # Keywords that indicate safe context
    dangerous_keywords: list[str]  # Keywords that indicate danger
    description: str = ""
    pattern_type: str = "regex"

    def evaluate(self, diff_content: str, code_snippet: str, file_path: str = "") -> tuple[bool, str]:
        """
        Evaluate if the pattern is safe in this context.
        Returns (is_safe, reason).
        """
        diff_str = diff_content or ""
        snippet_str = code_snippet or ""
        fp_str = file_path or ""
        combined = f"{diff_str} {snippet_str} {fp_str}".lower()

        # Check for dangerous keywords first
        for keyword in self.dangerous_keywords:
            if keyword.lower() in combined:
                return False, f"Found dangerous keyword: {keyword}"

        # Check for safe context keywords
        safe_context_found = False
        for keyword in self.context_keywords:
            if keyword.lower() in combined:
                safe_context_found = True
                break

        if safe_context_found:
            return True, f"Context matches safe pattern: {self.pattern}"

        # No clear context - be conservative
        return False, "No matching context found"


class FalsePositiveFilter:
    """
    Filters false positives from code analysis results.

    Strategies:
    1. Known safe patterns whitelist (persistent)
    2. Context-aware filtering (checks diff context)
    3. Pattern intersection with diff (compares findings to changes)
    4. Learning from corrections (adapts based on user feedback)
    """

    def __init__(self, whitelist_path: str | None = None):
        self.whitelist_path = whitelist_path or self._get_default_whitelist_path()
        self.whitelist: list[WhitelistEntry] = []
        self.context_patterns: list[ContextPattern] = []
        self.learning_data: dict[str, int] = {}  # pattern -> correction_count
        self._load_whitelist()
        self._init_context_patterns()

    def _get_default_whitelist_path(self) -> str:
        """Get default path for whitelist storage."""
        return str(Path(__file__).parent / "false_positive_whitelist.json")

    def _load_whitelist(self) -> None:
        """Load whitelist from disk."""
        if not self.whitelist_path or self.whitelist_path == ":memory:":
            return
        whitelist_file = Path(self.whitelist_path)
        if whitelist_file.exists():
            try:
                with open(whitelist_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self.whitelist = [
                        WhitelistEntry(**entry) for entry in data.get("entries", [])
                    ]
                    self.learning_data = data.get("learning_data", {})
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Warning: Could not load whitelist: {e}")
                self.whitelist = []

    def _save_whitelist(self) -> None:
        """Save whitelist to disk."""
        if not self.whitelist_path or self.whitelist_path == ":memory:":
            return
        whitelist_file = Path(self.whitelist_path)
        whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(whitelist_file, "w", encoding="utf-8") as f:
                json.dump({
                    "entries": [
                        {
                            "pattern": e.pattern,
                            "pattern_type": e.pattern_type,
                            "reason": e.reason,
                            "added_date": e.added_date,
                            "author": e.author,
                            "file_path": e.file_path,
                            "line_start": e.line_start,
                            "line_end": e.line_end,
                            "match_count": e.match_count,
                            "false_positive_count": e.false_positive_count,
                        }
                        for e in self.whitelist
                    ],
                    "learning_data": self.learning_data,
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save whitelist: {e}")

    def _init_context_patterns(self) -> None:
        """Initialize context-aware patterns for common false positive scenarios."""
        self.context_patterns = [
            ContextPattern(
                pattern=r"password\s*=\s*['\"].*['\"]",
                context_keywords=["test", "fixture", "mock", "example", "demo", "stub"],
                dangerous_keywords=["production", "prod", "secret", "key"],
                description="Hardcoded password in test/fixture code",
            ),
            ContextPattern(
                pattern=r"TODO|FIXME|HACK",
                context_keywords=["test", "mock", "stub"],
                dangerous_keywords=[],
                description="TODO comments in test code",
            ),
            ContextPattern(
                pattern=r"print\s*\(",
                context_keywords=["debug", "if __name__", "test", "logger"],
                dangerous_keywords=["production", "prod"],
                description="Debug print statements",
            ),
            ContextPattern(
                pattern=r"except\s*:\s*pass",
                context_keywords=["test", "mock", "fixture"],
                dangerous_keywords=["critical", "essential", "required"],
                description="Bare except in test code",
            ),
            ContextPattern(
                pattern=r"eval\s*\(",
                context_keywords=["test", "sandbox", "plugin", "extension"],
                dangerous_keywords=["user", "input", "request", "data"],
                description="Eval in safe contexts",
            ),
            ContextPattern(
                pattern=r"subprocess\.call|subprocess\.run",
                context_keywords=["test", "build", "script", "tool"],
                dangerous_keywords=["user", "input", "request"],
                description="Subprocess calls in build/test contexts",
            ),
            ContextPattern(
                pattern=r"\.env\b|\bAPI_KEY\s*=|\bSECRET\s*=",
                context_keywords=["example", "sample", "template", ".env.example"],
                dangerous_keywords=[],
                description="Env variables in example files",
            ),
        ]

    def add_to_whitelist(
        self,
        pattern: str,
        pattern_type: str,
        reason: str = "",
        author: str = "",
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
    ) -> None:
        """Add a new entry to the whitelist."""
        entry = WhitelistEntry(
            pattern=pattern,
            pattern_type=pattern_type,
            reason=reason,
            author=author,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
        )
        self.whitelist.append(entry)
        self._save_whitelist()

    def is_whitelisted(self, finding: Finding) -> bool:
        """Check if a finding matches any whitelist entry."""
        for entry in self.whitelist:
            if entry.matches(finding):
                entry.match_count += 1
                return True
        return False

    def _get_diff_context(self, file_path: str, line_number: int, diff_content: str, context_lines: int = 3) -> str:
        """Extract relevant context from diff for a finding."""
        if not diff_content:
            return ""

        lines = diff_content.split("\n")
        context = []
        found_file = False

        for i, line in enumerate(lines):
            if not line:
                continue
            if line.startswith("diff --git "):
                if found_file:
                    break  # Hit the next file
                if self._is_file_in_diff_header(line, file_path):
                    found_file = True
                    continue
            if not found_file and self._is_file_in_diff_header(line, file_path):
                found_file = True
                continue
            if found_file:
                if line.startswith(("+", "-", " ")):
                    stripped = line[1:].strip()
                    context.append(stripped)

        # Find lines near the finding
        relevant_context = []
        for line in context:
            relevant_context.append(line)

        return "\n".join(relevant_context[-context_lines * 2:])

    def _check_context_aware(
        self, finding: Finding, diff_content: str
    ) -> tuple[bool, str]:
        """Apply context-aware filtering."""
        for pattern in self.context_patterns:
            # Check if the finding matches the pattern
            if pattern.pattern_type == "regex":
                try:
                    if not re.search(pattern.pattern, finding.message, re.IGNORECASE):
                        if not re.search(pattern.pattern, finding.code_snippet, re.IGNORECASE):
                            continue
                except re.error:
                    continue
            elif pattern.pattern_type == "contains":
                if pattern.pattern.lower() not in finding.message.lower():
                    if pattern.pattern.lower() not in finding.code_snippet.lower():
                        continue
            else:
                if pattern.pattern not in finding.message:
                    if pattern.pattern not in finding.code_snippet:
                        continue

            # Evaluate context
            is_safe, reason = pattern.evaluate(
                diff_content or "", finding.code_snippet
            )
            if is_safe:
                return True, f"{pattern.description}: {reason}"

        return False, ""

    def _is_file_in_diff_header(self, line: str, norm_target: str) -> bool:
        """Kiểm tra header diff git khớp với đường dẫn tệp trên mọi nền tảng."""
        if not norm_target or not line:
            return False
        line_norm = line.replace("\\", "/").lower()
        for prefix in ("--- a/", "+++ b/", "diff --git a/"):
            if prefix in line_norm:
                parts = line_norm.split(prefix)
                if len(parts) > 1:
                    path_part = parts[1].split()[0].strip()
                    if _paths_match(path_part, norm_target):
                        return True
        if " b/" in line_norm:
            parts = line_norm.split(" b/")
            if len(parts) > 1:
                path_part = parts[1].split()[0].strip()
                if _paths_match(path_part, norm_target):
                    return True
        return f"a/{norm_target}" in line_norm or f"b/{norm_target}" in line_norm

    def _check_diff_intersection(
        self, finding: Finding, diff_content: str
    ) -> tuple[bool, str]:
        """
        Check if the finding's pattern intersects with actual changes in the diff.
        If the finding points to code that wasn't changed, it might be a false positive.
        """
        if not diff_content:
            return False, ""

        # Parse the diff to understand what changed
        lines = diff_content.split("\n")
        changed_lines_in_file = []
        in_target_file = False

        target_path = finding.file_path

        for line in lines:
            # Check for file headers
            if line.startswith("diff --git"):
                in_target_file = self._is_file_in_diff_header(line, target_path)
                continue
            if self._is_file_in_diff_header(line, target_path):
                in_target_file = True
                continue
            if line.startswith("@@") and in_target_file:
                continue
            if line.startswith("--- ") or line.startswith("+++ "):
                continue

            if in_target_file and line.startswith("+"):
                # This is an added line - get the content
                content = line[1:].strip()
                if content:
                    changed_lines_in_file.append(content)

        # Check if the finding's code snippet or message appears in the changed lines
        finding_signature = finding.code_snippet.strip() if finding.code_snippet else ""
        message_keywords = finding.message.split()[:5]  # First 5 words

        for changed_line in changed_lines_in_file:
            # Direct code match
            if finding_signature and finding_signature in changed_line:
                return False, ""  # Found in changes, likely legitimate

            # Keyword match in message
            keyword_matches = sum(
                1 for kw in message_keywords
                if len(kw) > 4 and kw.lower() in changed_line.lower()
            )
            if keyword_matches >= 3:
                return False, ""  # Significant overlap with changed code

        # Finding points to unchanged code - could be false positive
        return True, "Finding relates to unchanged code (not in diff)"

    def filter_results(
        self,
        results: list[Finding],
        diff_content: str = "",
        learn_from_corrections: bool = True,
    ) -> list[Finding]:
        """
        Filter false positives from a list of findings.

        Args:
            results: List of Finding objects to filter
            diff_content: The git diff content for context-aware filtering
            learn_from_corrections: Whether to apply learned corrections

        Returns:
            List of findings that are likely true positives
        """
        filtered = []

        for finding in results:
            reasons = []

            # 1. Check whitelist first (highest priority)
            if self.is_whitelisted(finding):
                reasons.append("Whitelisted")
                if learn_from_corrections:
                    self._record_learning(finding, is_false_positive=True)
                continue

            # 2. Check context-aware patterns
            is_safe_context, context_reason = self._check_context_aware(finding, diff_content)
            if is_safe_context:
                reasons.append(f"Context: {context_reason}")

            # 3. Check diff intersection
            is_unchanged, diff_reason = self._check_diff_intersection(finding, diff_content)
            if is_unchanged:
                reasons.append(f"Diff: {diff_reason}")

            # 4. Apply learned corrections
            if learn_from_corrections:
                correction_score = self._get_correction_score(finding)
                if correction_score > 2:  # Threshold for filtering
                    reasons.append(f"Learned: {correction_score} corrections")

            # Decision logic
            if len(reasons) >= 2:
                # Multiple indicators suggest false positive
                if learn_from_corrections:
                    self._record_learning(finding, is_false_positive=True)
                continue

            # Check severity - never filter critical/high severity
            if finding.severity in ("critical", "high", "error"):
                filtered.append(finding)
            elif reasons:
                # Some indicators but not enough to filter - include with caution
                finding.diff_context = context_reason or diff_reason
                filtered.append(finding)
            else:
                filtered.append(finding)

        return filtered

    def _record_learning(self, finding: Finding, is_false_positive: bool) -> None:
        """Record learning from a correction."""
        key = finding.signature

        if is_false_positive:
            self.learning_data[key] = self.learning_data.get(key, 0) + 1
        else:
            # False negative - reduce the score
            self.learning_data[key] = max(0, self.learning_data.get(key, 0) - 1)

        self._save_whitelist()

    def _get_correction_score(self, finding: Finding) -> int:
        """Get the correction score for a finding."""
        return self.learning_data.get(finding.signature, 0)

    def report_false_positive(
        self,
        finding: Finding,
        reason: str = "",
        add_to_whitelist: bool = False,
    ) -> None:
        """
        Report a false positive and optionally add to whitelist.

        Args:
            finding: The false positive finding
            reason: Why it's a false positive
            add_to_whitelist: Whether to add to permanent whitelist
        """
        self._record_learning(finding, is_false_positive=True)

        if add_to_whitelist:
            self.add_to_whitelist(
                pattern=finding.rule_id,
                pattern_type="rule_id",
                reason=reason or finding.message,
                file_path=finding.file_path,
                line_start=finding.line_number,
                line_end=finding.line_number,
            )

    def report_true_positive(self, finding: Finding) -> None:
        """Report a finding as a true positive (reinforces it)."""
        self._record_learning(finding, is_false_positive=False)

    def get_statistics(self) -> dict:
        """Get filter statistics."""
        return {
            "total_whitelist_entries": len(self.whitelist),
            "context_patterns": len(self.context_patterns),
            "learning_entries": len(self.learning_data),
            "top_corrected_patterns": sorted(
                self.learning_data.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }


def create_from_results(raw_results: list[dict]) -> list[Finding]:
    """Create Finding objects from raw result dictionaries."""
    return [Finding.from_dict(r) for r in raw_results]


def filter_raw_results(
    raw_results: list[dict],
    diff_content: str = "",
    whitelist_path: str | None = None,
) -> list[dict]:
    """
    Convenience function to filter raw result dictionaries.

    Args:
        raw_results: List of finding dictionaries
        diff_content: Git diff content
        whitelist_path: Optional path to whitelist file

    Returns:
        List of filtered finding dictionaries
    """
    findings = create_from_results(raw_results)
    filter_instance = FalsePositiveFilter(whitelist_path)
    filtered = filter_instance.filter_results(findings, diff_content)
    return [f.to_dict() for f in filtered]
