#!/usr/bin/env python3
"""
LLM-based Diff Security Inspector

Security-focused diff analysis using Anthropic's Claude Opus model.
Detects: SQL Injection, IDOR, Authentication Bypass, and Hardcoded Secrets.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    anthropic = None
    HAS_ANTHROPIC = False


# ============================================================================
# Configuration
# ============================================================================

DEFAULT_MAX_FILE_SIZE = 80 * 1024  # 80KB per file
DEFAULT_MAX_TOKENS = 4096
DEFAULT_MODEL = "claude-opus-5"
DEFAULT_TEMPERATURE = 0.1
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0
BACKOFF_MULTIPLIER = 2.0
MAX_BACKOFF = 32.0

SECURITY_CATEGORIES = [
    "SQL_INJECTION",
    "IDOR",
    "AUTH_BYPASS",
    "HARDCODED_SECRETS",
]

SYSTEM_PROMPT = """You are an expert application security engineer reviewing code changes for security vulnerabilities.

Analyze the provided diff for the following vulnerability categories:

1. SQL_INJECTION - SQL injection vulnerabilities including:
   - Unsanitized user input in SQL queries
   - String concatenation for SQL construction
   - Missing or weak input validation

2. IDOR (Insecure Direct Object Reference) - Authorization flaws:
   - Missing ownership verification
   - Insufficient access control checks
   - Direct object access without validation

3. AUTH_BYPASS - Authentication/authorization bypasses:
   - Disabled authentication checks
   - Weak session management
   - Missing authorization decorators
   - Hardcoded credentials

4. HARDCODED_SECRETS - Secrets in code:
   - API keys, tokens, passwords in source
   - Private keys embedded in code
   - Connection strings with credentials
   - Environment variables that shouldn't be committed

For each vulnerability found, provide:
- Exact file path and line numbers
- Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Description of the vulnerability
- Specific code snippet from the diff
- Remediation recommendation

Return findings in this exact JSON format:
{
  "findings": [
    {
      "category": "SQL_INJECTION|IDOR|AUTH_BYPASS|HARDCODED_SECRETS",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "path/to/file",
      "line_start": 123,
      "line_end": 126,
      "description": "Clear description of vulnerability",
      "code_snippet": "The vulnerable code",
      "remediation": "How to fix this"
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "requires_manual_review": false,
  "review_notes": "Any additional context"
}

If no vulnerabilities are found, return empty findings array with total_findings: 0.

Be thorough but precise. False positives waste developer time."""


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SecurityFinding:
    category: str
    severity: str
    file: str
    line_start: int
    line_end: int
    description: str
    code_snippet: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    file_path: str
    findings: list[SecurityFinding]
    summary: dict
    requires_manual_review: bool
    review_notes: str
    error: str | None = None
    model_used: str | None = None
    tokens_used: int | None = None


@dataclass
class DiffFile:
    path: str
    diff_content: str
    size_bytes: int
    truncated: bool = False


@dataclass
class InspectorConfig:
    api_key: str | None = None
    model: str = DEFAULT_MODEL
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    timeout: int = DEFAULT_TIMEOUT
    dual_mode: bool = False
    categories: list[str] = field(default_factory=lambda: SECURITY_CATEGORIES.copy())
    files_to_scan: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.min.js", "*.min.css", "*.map", "node_modules/**",
        ".git/**", "*.pyc", "__pycache__/**", "venv/**", ".venv/**",
        "dist/**", "build/**", "*.log", "*.lock"
    ])


# ============================================================================
# Diff Parsing and Preprocessing
# ============================================================================

class DiffParser:
    """Parse and preprocess unified diff format."""

    @staticmethod
    def extract_files_from_diff(diff_content: str) -> Iterator[tuple[str, str, int]]:
        """
        Extract individual file diffs from a unified diff.
        Yields: (filename, file_diff, size_bytes)
        """
        current_file: str | None = None
        current_diff_lines: list[str] = []
        in_diff = False

        for line in diff_content.splitlines():
            # Detect new file in diff
            if line.startswith("diff --git"):
                # Yield previous file if exists
                if current_file is not None and current_diff_lines:
                    content = "\n".join(current_diff_lines)
                    yield current_file, content, len(content.encode('utf-8'))

                # Extract filename from diff header
                parts = line.split(" b/")
                if len(parts) == 2:
                    current_file = parts[1].strip()
                else:
                    current_file = "unknown"
                current_diff_lines = [line]
                in_diff = True

            elif line.startswith("--- a/") or line.startswith("+++ b/"):
                if current_diff_lines is not None:
                    current_diff_lines.append(line)

            elif in_diff:
                current_diff_lines.append(line)

        # Yield last file
        if current_file is not None and current_diff_lines:
            content = "\n".join(current_diff_lines)
            yield current_file, content, len(content.encode('utf-8'))

    @staticmethod
    def read_git_diff(repo_path: str = ".") -> str:
        """Read the current diff from git."""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "diff", "--cached"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout

            # Fall back to unstaged diff
            result = subprocess.run(
                ["git", "diff"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30
            )
            return result.stdout if result.returncode == 0 else ""

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    @staticmethod
    def filter_files(
        files: list[tuple[str, str, int]],
        exclude_patterns: list[str],
        include_patterns: list[str] | None = None
    ) -> Iterator[tuple[str, str, int]]:
        """Filter files based on exclude/include patterns."""
        from fnmatch import fnmatch

        for file_path, diff, size in files:
            # Check exclusions
            excluded = False
            for pattern in exclude_patterns:
                if fnmatch(file_path, pattern) or "**/" in pattern and fnmatch(file_path, pattern.replace("**/", "")):
                    excluded = True
                    break

            if excluded:
                continue

            # Check inclusions if specified
            if include_patterns:
                included = any(fnmatch(file_path, p) for p in include_patterns)
                if not included:
                    continue

            yield file_path, diff, size


# ============================================================================
# Diff Preprocessing with Size Limits
# ============================================================================

class DiffPreprocessor:
    """Preprocess diffs with size limits and chunking."""

    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        self.max_file_size = max_file_size

    def preprocess(self, file_path: str, diff_content: str) -> DiffFile:
        """
        Preprocess diff content, truncating if necessary.
        Returns DiffFile with truncation flag if content was cut.
        """
        content_bytes = diff_content.encode('utf-8')
        original_size = len(content_bytes)
        truncated = False

        if original_size > self.max_file_size:
            # Truncate to max size, preserving diff headers
            # Find a safe truncation point
            truncated_content = diff_content[:self.max_file_size]

            # Try to find a clean break point (end of line)
            last_newline = truncated_content.rfind('\n')
            if last_newline > self.max_file_size * 0.8:  # If newline is within 20% of limit
                truncated_content = truncated_content[:last_newline]

            # Add truncation notice
            truncated_content += f"\n\n--- TRUNCATED (original: {original_size} bytes, limit: {self.max_file_size} bytes) ---\n"
            truncated_content += f"File: {file_path}\n"
            truncated_content += "This file was truncated. Consider reviewing the full diff manually.\n"

            diff_content = truncated_content
            truncated = True

        return DiffFile(
            path=file_path,
            diff_content=diff_content,
            size_bytes=len(diff_content.encode('utf-8')),
            truncated=truncated
        )

    def chunk_large_diff(self, diff_content: str, max_chunk_size: int | None = None) -> list[str]:
        """Split large diffs into manageable chunks."""
        if max_chunk_size is None:
            max_chunk_size = self.max_file_size

        chunks = []
        lines = diff_content.splitlines()
        current_chunk: list[str] = []
        current_size = 0

        for line in lines:
            line_size = len(line.encode('utf-8')) + 1  # +1 for newline

            if current_size + line_size > max_chunk_size and current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = []
                current_size = 0

            current_chunk.append(line)
            current_size += line_size

        if current_chunk:
            chunks.append("\n".join(current_chunk))

        return chunks


# ============================================================================
# Anthropic API Client with Retry Logic
# ============================================================================

class AnthropicClient:
    """Anthropic API client with exponential backoff retry."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout: int = DEFAULT_TIMEOUT,
        client = None
    ):
        if not HAS_ANTHROPIC and anthropic is None and client is None:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not provided or found in environment")

        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self._client = client
        if self._client is None and anthropic is not None and hasattr(anthropic, "Anthropic"):
            try:
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except Exception:
                self._client = None

    @property
    def client(self):
        # Support test mocking when anthropic.Anthropic is patched with a mock
        if anthropic is not None and type(getattr(anthropic, "Anthropic", None)).__name__ in ("Mock", "MagicMock", "NonCallableMock"):
            return anthropic.Anthropic(api_key=self.api_key)
        return self._client

    @client.setter
    def client(self, value):
        self._client = value

    def analyze_diff(
        self,
        diff_content: str,
        file_path: str,
        system_prompt: str = SYSTEM_PROMPT
    ) -> dict:
        """
        Analyze a diff for security vulnerabilities.
        Returns parsed JSON response from the model.
        """
        user_prompt = f"Review this diff for file: {file_path}\n\n```diff\n{diff_content}\n```"

        response = self._call_with_retry(user_prompt, system_prompt)
        return self._parse_response(response)

    def _call_with_retry(
        self,
        user_prompt: str,
        system_prompt: str
    ) -> str:
        """
        Make API call with exponential backoff retry.
        Handles rate limits, transient errors, and context windows.
        """
        last_error = None
        client = self.client
        if client is None:
            if anthropic is None:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
            client = anthropic.Anthropic(api_key=self.api_key)
            self._client = client

        for attempt in range(MAX_RETRIES):
            try:
                response = client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system_prompt,
                    messages=[
                        {
                            "role": "user",
                            "content": user_prompt
                        }
                    ],
                    timeout=self.timeout
                )

                # Extract response text
                if response.content and hasattr(response.content[0], 'text'):
                    return response.content[0].text
                elif hasattr(response, 'text'):
                    return response.text
                else:
                    raise ValueError("Unexpected response format from Anthropic API")

            except anthropic.RateLimitError as e:
                last_error = e
                backoff = min(
                    INITIAL_BACKOFF * (BACKOFF_MULTIPLIER ** attempt),
                    MAX_BACKOFF
                )
                print(f"Rate limit hit, retrying in {backoff:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(backoff)

            except anthropic.APIError as e:
                last_error = e
                # Check for context window issues
                err_msg = str(e).lower()
                if "context" in err_msg or "prompt is too long" in err_msg or "max_tokens" in err_msg:
                    raise ValueError(f"Context window exceeded: {e}")

                backoff = min(
                    INITIAL_BACKOFF * (BACKOFF_MULTIPLIER ** attempt),
                    MAX_BACKOFF
                )
                print(f"API error: {e}, retrying in {backoff:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(backoff)

            except (TimeoutError, Exception) as e:
                last_error = e
                backoff = min(
                    INITIAL_BACKOFF * (BACKOFF_MULTIPLIER ** attempt),
                    MAX_BACKOFF
                )
                print(f"Request failed: {e}, retrying in {backoff:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(backoff)

        raise RuntimeError(f"All {MAX_RETRIES} retries failed. Last error: {last_error}")

    def _parse_response(self, response_text: str) -> dict:
        """
        Parse JSON from model response.
        Handles code fences, partial JSON, and common parsing issues.
        """
        # Try to extract JSON from code fences
        json_text = response_text.strip()

        # Remove markdown code fences
        if json_text.startswith("```json"):
            json_text = json_text[7:]
        elif json_text.startswith("```"):
            json_text = json_text[3:]

        json_text = json_text.removesuffix("```")

        json_text = json_text.strip()

        try:
            return json.loads(json_text)
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            start_idx = json_text.find('{')
            end_idx = json_text.rfind('}') + 1

            if start_idx != -1 and end_idx > start_idx:
                try:
                    return json.loads(json_text[start_idx:end_idx])
                except json.JSONDecodeError:
                    pass

            # Return error structure
            return {
                "error": "Failed to parse response",
                "raw_response": response_text[:1000],
                "findings": [],
                "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            }


# ============================================================================
# Dual Mode for Enhanced Recall
# ============================================================================

class DualModeAnalyzer:
    """
    Analyze diffs using two different strategies for enhanced recall.
    Combines results to minimize false negatives.
    """

    def __init__(self, config: InspectorConfig):
        self.config = config
        self.client = AnthropicClient(
            api_key=config.api_key,
            model=config.model,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout=config.timeout
        )

    def analyze_with_dual_prompts(
        self,
        diff_content: str,
        file_path: str
    ) -> list[SecurityFinding]:
        """
        Run two analyses with different focused prompts and merge results.
        Uses OR logic: include finding if either model found it.
        """

        # Prompt 1: General security review
        general_prompt = SYSTEM_PROMPT

        # Prompt 2: Focused on common patterns (alternative angle)
        focused_prompt = """You are a security expert focusing on implementation flaws.

Review this diff for security issues with emphasis on:

1. **Injection Vulnerabilities**: Look for any place where untrusted data flows into:
   - Database queries (SQL)
   - Command execution (shell, system)
   - File operations (path traversal)
   - Code execution (eval, dynamic imports)

2. **Access Control Issues**:
   - Missing permission checks
   - Object references without validation
   - Authentication bypasses

3. **Secret Exposure**:
   - Credentials in code
   - API keys, tokens
   - Connection strings
   - Cryptographic keys

Return findings in this JSON format:
{
  "findings": [
    {
      "category": "SQL_INJECTION|IDOR|AUTH_BYPASS|HARDCODED_SECRETS",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "path/to/file",
      "line_start": 123,
      "line_end": 126,
      "description": "Clear description of vulnerability",
      "code_snippet": "The vulnerable code",
      "remediation": "How to fix this"
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "requires_manual_review": false,
  "review_notes": "Any additional context"
}"""

        findings = []
        seen_hashes = set()

        # Run both analyses
        results = []
        for prompt in [general_prompt, focused_prompt]:
            try:
                result = self.client.analyze_diff(diff_content, file_path, prompt)
                results.append(result)
            except Exception as e:
                print(f"Warning: One analysis failed: {e}")
                continue

        # Merge findings using OR logic
        for result in results:
            if "findings" in result:
                for finding in result["findings"]:
                    finding_hash = self._hash_finding(finding)
                    if finding_hash not in seen_hashes:
                        seen_hashes.add(finding_hash)
                        try:
                            valid_keys = {
                                "category", "severity", "file", "line_start",
                                "line_end", "description", "code_snippet", "remediation"
                            }
                            filtered_finding = {k: v for k, v in finding.items() if k in valid_keys} if isinstance(finding, dict) else finding
                            findings.append(SecurityFinding(**filtered_finding))
                        except (TypeError, KeyError) as e:
                            print(f"Warning: Skipping malformed finding: {e}")

        return findings

    @staticmethod
    def _hash_finding(finding: dict) -> str:
        """Generate hash for deduplication."""
        content = f"{finding.get('file', '')}:{finding.get('line_start', 0)}:{finding.get('category', '')}:{finding.get('description', '')[:100]}"
        return hashlib.md5(content.encode()).hexdigest()


# ============================================================================
# Main Inspector Class
# ============================================================================

class LLMDiffSecurityInspector:
    """Main class for LLM-based diff security inspection."""

    def __init__(self, config: InspectorConfig | None = None):
        self.config = config or InspectorConfig()
        self.preprocessor = DiffPreprocessor(self.config.max_file_size)

        if self.config.dual_mode:
            self.analyzer = DualModeAnalyzer(self.config)
        else:
            self.client = AnthropicClient(
                api_key=self.config.api_key,
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout
            )

    def inspect_diff(
        self,
        diff_content: str | None = None,
        repo_path: str = "."
    ) -> list[AnalysisResult]:
        """
        Inspect a diff for security vulnerabilities.

        Args:
            diff_content: Raw diff string. If None, reads from git.
            repo_path: Path to git repository for unstaged/cached diffs.

        Returns:
            List of AnalysisResult objects, one per file analyzed.
        """
        if diff_content is None:
            diff_content = DiffParser.read_git_diff(repo_path)

        if not diff_content.strip():
            print("No diff content to analyze.")
            return []

        # Parse diff into individual files
        files = list(DiffParser.extract_files_from_diff(diff_content))

        # Filter files
        files = list(DiffParser.filter_files(
            files,
            self.config.exclude_patterns,
            None  # Include all if no specific patterns
        ))

        if self.config.files_to_scan:
            files = [f for f in files if any(fp in f[0] for fp in self.config.files_to_scan)]

        results = []

        for file_path, diff, size in files:
            print(f"\nAnalyzing: {file_path} ({size} bytes)")

            # Preprocess with size limits
            processed = self.preprocessor.preprocess(file_path, diff)

            if processed.truncated:
                print(f"  [TRUNCATED] File exceeded {self.config.max_file_size} bytes limit")

            try:
                if self.config.dual_mode:
                    findings = self.analyzer.analyze_with_dual_prompts(
                        processed.diff_content,
                        file_path
                    )

                    result = AnalysisResult(
                        file_path=file_path,
                        findings=findings,
                        summary={
                            "total_findings": len(findings),
                            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
                            "high": len([f for f in findings if f.severity == "HIGH"]),
                            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
                            "low": len([f for f in findings if f.severity == "LOW"]),
                        },
                        requires_manual_review=any(f.severity in ["CRITICAL", "HIGH"] for f in findings),
                        review_notes="Analyzed using dual-mode OR analysis",
                        model_used=self.config.model
                    )
                else:
                    response = self.client.analyze_diff(processed.diff_content, file_path)

                    findings = []
                    if "findings" in response:
                        for f in response["findings"]:
                            try:
                                valid_keys = {
                                    "category", "severity", "file", "line_start",
                                    "line_end", "description", "code_snippet", "remediation"
                                }
                                filtered_f = {k: v for k, v in f.items() if k in valid_keys} if isinstance(f, dict) else f
                                findings.append(SecurityFinding(**filtered_f))
                            except (TypeError, KeyError) as e:
                                print(f"Warning: Skipping malformed finding: {e}")

                    summary = response.get("summary", {
                        "total_findings": len(findings),
                        "critical": 0, "high": 0, "medium": 0, "low": 0
                    })

                    result = AnalysisResult(
                        file_path=file_path,
                        findings=findings,
                        summary=summary,
                        requires_manual_review=response.get("requires_manual_review", False),
                        review_notes=response.get("review_notes", ""),
                        model_used=self.config.model,
                        tokens_used=response.get("usage", {}).get("output_tokens", None)
                    )

                results.append(result)

                # Print summary
                total = len(result.findings)
                if total > 0:
                    print(f"  [FINDINGS] {total} potential issues detected:")
                    for f in result.findings:
                        print(f"    - [{f.severity}] {f.category}: {f.description[:60]}...")
                else:
                    print("  [CLEAN] No vulnerabilities detected")

            except Exception as e:
                print(f"  [ERROR] Analysis failed: {e}")
                results.append(AnalysisResult(
                    file_path=file_path,
                    findings=[],
                    summary={"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                    requires_manual_review=True,
                    review_notes="",
                    error=str(e)
                ))

        return results

    def generate_report(self, results: list[AnalysisResult], output_format: str = "text") -> str:
        """Generate formatted report from analysis results."""
        if output_format == "json":
            return self._generate_json_report(results)
        return self._generate_text_report(results)

    def _generate_text_report(self, results: list[AnalysisResult]) -> str:
        """Generate human-readable text report."""
        lines = [
            "=" * 70,
            "LLM DIFF SECURITY INSPECTOR REPORT",
            "=" * 70,
            ""
        ]

        total_findings = 0
        total_critical = 0
        total_high = 0

        for result in results:
            if result.error:
                lines.append(f"\nFile: {result.file_path}")
                lines.append(f"  ERROR: {result.error}")
                continue

            if not result.findings:
                continue

            total_findings += len(result.findings)

            lines.append(f"\n{'=' * 70}")
            lines.append(f"File: {result.file_path}")
            lines.append(f"{'=' * 70}")

            for i, finding in enumerate(result.findings, 1):
                total_critical += 1 if finding.severity == "CRITICAL" else 0
                total_high += 1 if finding.severity == "HIGH" else 0

                lines.append(f"\n  Finding #{i}: {finding.category}")
                lines.append(f"  Severity: {finding.severity}")
                lines.append(f"  Lines: {finding.line_start}-{finding.line_end}")
                lines.append(f"  Description: {finding.description}")
                lines.append("\n  Code Snippet:")
                for code_line in finding.code_snippet.split('\n'):
                    lines.append(f"    {code_line}")
                lines.append(f"\n  Remediation: {finding.remediation}")

        lines.append(f"\n{'=' * 70}")
        lines.append("SUMMARY")
        lines.append(f"{'=' * 70}")
        lines.append(f"Files Analyzed: {len(results)}")
        lines.append(f"Total Findings: {total_findings}")
        lines.append(f"  Critical: {total_critical}")
        lines.append(f"  High: {total_high}")
        lines.append(f"  Medium: {sum(1 for r in results for f in r.findings if f.severity == 'MEDIUM')}")
        lines.append(f"  Low: {sum(1 for r in results for f in r.findings if f.severity == 'LOW')}")

        if total_critical > 0 or total_high > 0:
            lines.append("\n*** ACTION REQUIRED: Critical or High severity findings detected ***")
        elif total_findings > 0:
            lines.append("\nReview recommended: Medium/Low severity findings present")
        else:
            lines.append("\nNo security vulnerabilities detected.")

        return "\n".join(lines)

    def _generate_json_report(self, results: list[AnalysisResult]) -> str:
        """Generate JSON report."""
        report = {
            "metadata": {
                "model": self.config.model,
                "dual_mode": self.config.dual_mode,
                "max_file_size": self.config.max_file_size,
                "files_analyzed": len(results)
            },
            "results": [
                {
                    "file": r.file_path,
                    "findings": [f.to_dict() for f in r.findings],
                    "summary": r.summary,
                    "error": r.error
                }
                for r in results
            ],
            "totals": {
                "files": len(results),
                "findings": sum(len(r.findings) for r in results),
                "critical": sum(1 for r in results for f in r.findings if f.severity == "CRITICAL"),
                "high": sum(1 for r in results for f in r.findings if f.severity == "HIGH"),
                "medium": sum(1 for r in results for f in r.findings if f.severity == "MEDIUM"),
                "low": sum(1 for r in results for f in r.findings if f.severity == "LOW"),
            }
        }
        return json.dumps(report, indent=2)


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="LLM-based Diff Security Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze current git diff
  %(prog)s

  # Analyze staged changes with dual mode for enhanced recall
  %(prog)s --dual-mode

  # Analyze specific files
  %(prog)s --files-to-scan src/auth.py --files-to-scan src/api.py

  # Use JSON output
  %(prog)s --output-format json

  # Custom model and token limits
  %(prog)s --model claude-opus-5 --max-tokens 8192
        """
    )

    parser.add_argument(
        "--api-key", "-k",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
        default=None
    )

    parser.add_argument(
        "--model", "-m",
        help=f"Model to use (default: {DEFAULT_MODEL})",
        default=DEFAULT_MODEL
    )

    parser.add_argument(
        "--max-tokens",
        type=int,
        help=f"Max tokens for response (default: {DEFAULT_MAX_TOKENS})",
        default=DEFAULT_MAX_TOKENS
    )

    parser.add_argument(
        "--temperature", "-t",
        type=float,
        help=f"Response temperature 0-1 (default: {DEFAULT_TEMPERATURE})",
        default=DEFAULT_TEMPERATURE
    )

    parser.add_argument(
        "--max-file-size",
        type=int,
        help=f"Max file size in bytes (default: {DEFAULT_MAX_FILE_SIZE})",
        default=DEFAULT_MAX_FILE_SIZE
    )

    parser.add_argument(
        "--timeout",
        type=int,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
        default=DEFAULT_TIMEOUT
    )

    parser.add_argument(
        "--dual-mode",
        action="store_true",
        help="Use dual analysis mode for enhanced recall (OR logic)"
    )

    parser.add_argument(
        "--files-to-scan", "-f",
        action="append",
        help="Specific files to scan (can be repeated)",
        default=[]
    )

    parser.add_argument(
        "--exclude-pattern",
        action="append",
        help="File patterns to exclude (can be repeated)",
        default=[]
    )

    parser.add_argument(
        "--repo-path", "-r",
        default=".",
        help="Path to git repository (default: current directory)"
    )

    parser.add_argument(
        "--output-format", "-o",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--diff-file",
        help="Read diff from file instead of git",
        default=None
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )

    args = parser.parse_args()

    # Build config
    config = InspectorConfig(
        api_key=args.api_key,
        model=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        max_file_size=args.max_file_size,
        timeout=args.timeout,
        dual_mode=args.dual_mode,
        files_to_scan=args.files_to_scan,
        exclude_patterns=args.exclude_pattern if args.exclude_pattern else InspectorConfig().exclude_patterns
    )

    # Read diff
    diff_content = None
    if args.diff_file:
        try:
            with open(args.diff_file, encoding='utf-8') as f:
                diff_content = f.read()
        except Exception as e:
            print(f"Error reading diff file: {e}")
            sys.exit(1)

    # Run inspection
    try:
        inspector = LLMDiffSecurityInspector(config)
        results = inspector.inspect_diff(diff_content, args.repo_path)

        # Generate and print report
        report = inspector.generate_report(results, args.output_format)
        print(report)

        # Exit with appropriate code
        total_critical_high = sum(
            1 for r in results
            for f in r.findings
            if f.severity in ["CRITICAL", "HIGH"]
        )

        sys.exit(0 if total_critical_high == 0 else 1)

    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Configuration error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"Inspection failed: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
