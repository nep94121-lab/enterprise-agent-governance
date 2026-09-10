#!/usr/bin/env python3
"""
Integration Utilities for Hooks.

Common helpers for all hooks including file operations, config management,
logging, path utilities, serialization, error handling, and timing helpers.
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Generic,
    ParamSpec,
    TypeVar,
)

# ============================================================================
# Type Variables
# ============================================================================

P = ParamSpec("P")
T = TypeVar("T")


# ============================================================================
# Enumerations
# ============================================================================

class LogLevel(str, Enum):
    """Log level enumeration matching standard logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ConfigFormat(str, Enum):
    """Supported configuration file formats."""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    INI = "ini"
    ENV = "env"


class FileAction(str, Enum):
    """File operation actions."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    READ = "read"


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class FileMetadata:
    """Metadata for a file operation."""
    path: str
    size: int = 0
    modified: str | None = None
    checksum: str | None = None
    action: FileAction = FileAction.READ
    success: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConfigEntry:
    """A configuration entry."""
    key: str
    value: Any
    source: str | None = None
    type_hint: str | None = None
    modified: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HookContext:
    """Context information for hook execution."""
    hook_name: str
    repo_root: Path
    working_dir: Path | None = None
    config_dir: Path | None = None
    environment: str = "development"
    dry_run: bool = False
    verbose: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["repo_root"] = str(self.repo_root)
        result["working_dir"] = str(self.working_dir) if self.working_dir else None
        result["config_dir"] = str(self.config_dir) if self.config_dir else None
        return result

    @classmethod
    def from_env(cls, hook_name: str = "unknown") -> HookContext:
        """Create context from environment variables."""
        repo_root = Path.cwd()
        return cls(
            hook_name=hook_name,
            repo_root=repo_root,
            working_dir=Path.cwd(),
            config_dir=repo_root / ".claude",
            environment=os.getenv("ENVIRONMENT", "development"),
            dry_run=os.getenv("DRY_RUN", "").lower() in ("1", "true", "yes"),
            verbose=os.getenv("VERBOSE", "").lower() in ("1", "true", "yes"),
        )


@dataclass
class OperationResult:
    """Result of a hook operation."""
    success: bool
    message: str
    data: Any = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: float = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimingRecord:
    """Record of an operation's timing."""
    operation: str
    start_time: float
    end_time: float = 0
    duration_ms: float = 0
    success: bool = True

    def finish(self) -> float:
        """Mark operation as finished and return duration."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        return self.duration_ms


# ============================================================================
# File Operations
# ============================================================================

def ensure_dir(path: Path | str) -> Path:
    """Ensure a directory exists, creating it if necessary."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_file(path: Path | str, encoding: str = "utf-8") -> str:
    """Read a file and return its contents."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return path.read_text(encoding=encoding)


def write_file(path: Path | str, content: str, encoding: str = "utf-8") -> FileMetadata:
    """Write content to a file and return metadata."""
    path = Path(path)
    ensure_dir(path.parent)

    old_checksum = None
    if path.exists():
        old_checksum = file_checksum(path)

    path.write_text(content, encoding=encoding)

    return FileMetadata(
        path=str(path),
        size=len(content),
        modified=datetime.now(UTC).isoformat(),
        checksum=file_checksum(path),
        action=FileAction.UPDATE if old_checksum else FileAction.CREATE,
    )


def file_checksum(path: Path | str, algorithm: str = "sha256") -> str:
    """Calculate checksum of a file."""
    path = Path(path)
    if not path.exists():
        return ""

    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_file_metadata(path: Path | str) -> FileMetadata:
    """Get metadata for a file."""
    path = Path(path)
    if not path.exists():
        return FileMetadata(path=str(path), success=False, error="File not found")

    stat = path.stat()
    return FileMetadata(
        path=str(path),
        size=stat.st_size,
        modified=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
        checksum=file_checksum(path),
    )


def find_files(
    root: Path | str,
    pattern: str = "*",
    recursive: bool = True,
    include_hidden: bool = False,
) -> list[Path]:
    """Find files matching a glob pattern."""
    root = Path(root)
    pattern = pattern or "*"

    if recursive:
        matches = root.rglob(pattern)
    else:
        matches = root.glob(pattern)

    result = []
    for path in matches:
        if path.is_file():
            if include_hidden or not path.name.startswith("."):
                result.append(path)

    return sorted(result)


def filter_by_patterns(paths: list[Path], include: list[str], exclude: list[str]) -> list[Path]:
    """Filter paths by include/exclude patterns."""
    result = paths

    if exclude:
        excluded = set()
        for path in result:
            path_str = str(path)
            for pattern in exclude:
                if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                    excluded.add(path)
                    break
        result = [p for p in result if p not in excluded]

    if include:
        filtered = []
        for path in result:
            path_str = str(path)
            for pattern in include:
                if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                    filtered.append(path)
                    break
        result = filtered

    return result


# ============================================================================
# Serialization / Config
# ============================================================================

def load_json(path: Path | str) -> dict | list:
    """Load JSON from a file."""
    path = Path(path)
    if not path.exists():
        return {} if path.suffix == ".json" else []

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path | str, data: Any, indent: int = 2) -> None:
    """Save data as JSON to a file."""
    path = Path(path)
    ensure_dir(path.parent)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def merge_configs(*configs: dict) -> dict:
    """Deep merge multiple configuration dictionaries."""
    result = {}

    for config in configs:
        if not isinstance(config, dict):
            continue

        for key, value in config.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = merge_configs(result[key], value)
            else:
                result[key] = value

    return result


def get_nested(data: dict, key_path: str, default: Any = None) -> Any:
    """Get a nested value from a dictionary using dot notation."""
    keys = key_path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default

    return current


def set_nested(data: dict, key_path: str, value: Any) -> None:
    """Set a nested value in a dictionary using dot notation."""
    keys = key_path.split(".")
    current = data

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value


def serialize_value(value: Any) -> str:
    """Serialize a value to a string representation."""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return value
    elif isinstance(value, (list, tuple)):
        return ", ".join(serialize_value(v) for v in value)
    elif isinstance(value, dict):
        return json.dumps(value)
    elif isinstance(value, Enum):
        return value.value
    elif is_dataclass(value):
        return json.dumps(asdict(value))
    else:
        return str(value)


def deserialize_value(value: str, target_type: type[T]) -> T | None:
    """Deserialize a string to a target type."""
    if value in ("null", "None", ""):
        return None

    if target_type is bool:
        return value.lower() in ("true", "1", "yes", "on")
    elif target_type is int:
        try:
            return int(value)
        except ValueError:
            return None
    elif target_type is float:
        try:
            return float(value)
        except ValueError:
            return None
    elif target_type is str:
        return value
    elif target_type is list:
        return [v.strip() for v in value.split(",") if v.strip()]
    elif target_type is dict:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    return None


# ============================================================================
# Path Utilities
# ============================================================================

def normalize_path(path: Path | str, base: Path | None = None) -> Path:
    """Normalize and resolve a path."""
    path = Path(path)

    if not path.is_absolute() and base:
        path = base / path

    return path.resolve()


def relative_to(path: Path | str, base: Path | str) -> Path:
    """Get path relative to base."""
    return Path(path).relative_to(Path(base))


def is_subpath(path: Path | str, parent: Path | str) -> bool:
    """Check if path is a subpath of parent."""
    try:
        Path(path).relative_to(Path(parent))
        return True
    except ValueError:
        return False


def expand_path(path: str) -> Path:
    """Expand user home and environment variables in path."""
    return Path(os.path.expandvars(os.path.expanduser(path)))


def get_project_root(start: Path | None = None) -> Path:
    """Find project root by looking for common markers."""
    if start is None:
        start = Path.cwd()
    else:
        start = Path(start)

    markers = [
        ".git",
        "pyproject.toml",
        "package.json",
        "Cargo.toml",
        "go.mod",
        ".claude",
        "CLAUDE.md",
    ]

    current = start
    while current != current.parent:
        for marker in markers:
            if (current / marker).exists():
                return current
        current = current.parent

    return start


def find_config_file(
    name: str,
    search_dirs: list[Path] | None = None,
    search_parents: bool = True,
) -> Path | None:
    """Find a config file by searching directories."""
    if search_dirs:
        for directory in search_dirs:
            path = Path(directory) / name
            if path.exists():
                return path.resolve()

    if search_parents:
        current = Path.cwd()
        while current != current.parent:
            path = current / name
            if path.exists():
                return path.resolve()
            current = current.parent

    return None


# ============================================================================
# Logging
# ============================================================================

class SimpleLogger:
    """Simple logger with colored output support."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def __init__(
        self,
        name: str = "hooks",
        level: LogLevel = LogLevel.INFO,
        use_colors: bool = True,
        file_path: Path | str | None = None,
    ):
        self.name = name
        self.level = level
        self.use_colors = use_colors and sys.stderr.isatty()
        self._file = None

        if file_path:
            self._file = open(file_path, "a", encoding="utf-8")

    def close(self) -> None:
        """Close file handle if open."""
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> SimpleLogger:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _format(
        self,
        level: LogLevel,
        message: str,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Format a log message."""
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{timestamp}] [{level.value}] {self.name}"

        if extra:
            extra_str = " ".join(f"{k}={serialize_value(v)}" for k, v in extra.items())
            message = f"{message} {extra_str}"

        return f"{prefix}: {message}"

    def _write(self, level: LogLevel, message: str) -> None:
        """Write a log message."""
        if self.level == LogLevel.DEBUG or level.value not in ("DEBUG",):
            pass

        levels = list(LogLevel)
        if levels.index(level) < levels.index(self.level):
            return

        formatted = self._format(level, message)

        if self.use_colors:
            color = self.COLORS.get(level.value, "")
            reset = self.COLORS["RESET"]
            formatted = f"{color}{formatted}{reset}"

        print(formatted, file=sys.stderr)

        if self._file:
            self._file.write(formatted + "\n")
            self._file.flush()

    def debug(self, message: str, **extra: Any) -> None:
        """Log debug message."""
        self._write(LogLevel.DEBUG, message)

    def info(self, message: str, **extra: Any) -> None:
        """Log info message."""
        self._write(LogLevel.INFO, message)

    def warning(self, message: str, **extra: Any) -> None:
        """Log warning message."""
        self._write(LogLevel.WARNING, message)

    def error(self, message: str, **extra: Any) -> None:
        """Log error message."""
        self._write(LogLevel.ERROR, message)

    def critical(self, message: str, **extra: Any) -> None:
        """Log critical message."""
        self._write(LogLevel.CRITICAL, message)


# Global default logger
_default_logger: SimpleLogger | None = None


def get_logger(
    name: str = "hooks",
    level: LogLevel = LogLevel.INFO,
) -> SimpleLogger:
    """Get or create the default logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = SimpleLogger(name=name, level=level)
    return _default_logger


# ============================================================================
# Error Handling
# ============================================================================

class HookError(Exception):
    """Base exception for hook errors."""

    def __init__(
        self,
        message: str,
        code: str = "HOOK_ERROR",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigError(HookError):
    """Configuration related error."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="CONFIG_ERROR", details=details)


class FileError(HookError):
    """File operation error."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="FILE_ERROR", details=details)


class ValidationError(HookError):
    """Validation error."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="VALIDATION_ERROR", details=details)


def handle_errors(
    default_return: T = None,
    log_errors: bool = True,
    reraise: bool = False,
) -> Callable[[Callable[P, T]], Callable[P, T | None]]:
    """Decorator to handle errors in hook functions."""
    def decorator(func: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
            try:
                return func(*args, **kwargs)
            except HookError:
                if reraise:
                    raise
                if log_errors:
                    logger = get_logger()
                    logger.error(f"Hook error in {func.__name__}: {type(HookError).__name__}")
                return default_return
            except Exception as e:
                if reraise:
                    raise
                if log_errors:
                    logger = get_logger()
                    logger.error(f"Unexpected error in {func.__name__}: {e}")
                return default_return
        return wrapper
    return decorator


def safe_execute(
    func: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> tuple[bool, T | None, str | None]:
    """Safely execute a function and return success status, result, and error."""
    try:
        result = func(*args, **kwargs)
        return True, result, None
    except Exception as e:
        return False, None, str(e)


# ============================================================================
# Timing
# ============================================================================

class Timer:
    """Context manager for timing operations."""

    def __init__(self, name: str = "operation", log: bool = False):
        self.name = name
        self.log = log
        self.start_time = 0.0
        self.end_time = 0.0
        self.duration_ms = 0.0

    def __enter__(self) -> Timer:
        self.start_time = time.time()
        return self

    def __exit__(self, *args: object) -> None:
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000

        if self.log:
            logger = get_logger()
            logger.debug(f"{self.name} took {self.duration_ms:.2f}ms")

    def to_record(self) -> TimingRecord:
        """Convert to timing record."""
        return TimingRecord(
            operation=self.name,
            start_time=self.start_time,
            end_time=self.end_time,
            duration_ms=self.duration_ms,
        )


def timeit(func: Callable[P, T]) -> Callable[P, tuple[T, float]]:
    """Decorator to time a function."""
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> tuple[T, float]:
        start = time.time()
        result = func(*args, **kwargs)
        duration_ms = (time.time() - start) * 1000
        return result, duration_ms
    return wrapper


def rate_limit(
    max_calls: int,
    window_seconds: float,
) -> Callable[[Callable[P, T]], Callable[P, T | None]]:
    """Decorator to rate limit a function."""
    calls: list[float] = []

    def decorator(func: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
            now = time.time()

            # Remove old calls outside window
            cutoff = now - window_seconds
            calls[:] = [t for t in calls if t > cutoff]

            if len(calls) >= max_calls:
                return None

            calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# Caching
# ============================================================================

class TTLCache(Generic[T]):
    """Simple time-to-live cache."""

    def __init__(self, ttl_seconds: float = 60):
        self._cache: dict[str, tuple[T, float]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> T | None:
        """Get value from cache if not expired."""
        if key not in self._cache:
            return None

        value, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl:
            del self._cache[key]
            return None

        return value

    def set(self, key: str, value: T) -> None:
        """Set value in cache."""
        self._cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None


def memoize(func: Callable[P, T]) -> Callable[P, T]:
    """Simple memoization decorator with TTL."""
    cache: dict[str, T] = {}
    last_clear = [time.time()]
    ttl = 300  # 5 minutes default TTL

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        # Clear cache periodically
        if time.time() - last_clear[0] > ttl:
            cache.clear()
            last_clear[0] = time.time()

        key = str(args) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]

    wrapper.cache_clear = cache.clear  # type: ignore
    return wrapper


# ============================================================================
# Command Execution
# ============================================================================

def run_command(
    cmd: list[str],
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 30,
    capture: bool = True,
) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    process = None
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=merged_env,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
        )

        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout or "", stderr or ""

    except subprocess.TimeoutExpired:
        if process:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
            finally:
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        if process:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
            finally:
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
        return -1, "", str(e)


def check_command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    if os.name == "nt":
        result = run_command(["where", cmd], capture=True, timeout=5)
    else:
        result = run_command(["which", cmd], capture=True, timeout=5)
    return result[0] == 0


# ============================================================================
# Git Utilities
# ============================================================================

def is_git_repo(path: Path | None = None) -> bool:
    """Check if path is a git repository."""
    path = path or Path.cwd()
    git_dir = path / ".git"
    return git_dir.exists() and git_dir.is_dir()


def get_git_root() -> Path | None:
    """Get the git repository root."""
    result = run_command(["git", "rev-parse", "--show-toplevel"], capture=True)
    if result[0] == 0:
        return Path(result[1].strip())
    return None


def get_git_diff(path: Path | None = None, staged: bool = False) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    if path:
        cmd.append(str(path))

    result = run_command(cmd, capture=True)
    return result[1] if result[0] == 0 else ""


def get_changed_files(base: str = "HEAD", include_untracked: bool = True) -> list[str]:
    """Get list of changed files since base commit."""
    files: list[str] = []

    # 1. Get tracked changed files compared to base commit
    cmd = ["git", "diff", "--name-only", base]
    result = run_command(cmd, capture=True)
    if result[0] == 0:
        files.extend(f.strip() for f in result[1].split("\n") if f.strip())

    # 2. Get untracked files via git ls-files if requested
    if include_untracked:
        untracked_cmd = ["git", "ls-files", "--others", "--exclude-standard"]
        untracked_result = run_command(untracked_cmd, capture=True)
        if untracked_result[0] == 0:
            files.extend(f.strip() for f in untracked_result[1].split("\n") if f.strip())

    # 3. Deduplicate while preserving order
    seen = set()
    unique_files = []
    for f in files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    return unique_files


def get_current_branch() -> str | None:
    """Get the current git branch."""
    result = run_command(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture=True,
    )
    if result[0] == 0:
        return result[1].strip()
    return None


# ============================================================================
# Validation
# ============================================================================

def validate_file_path(path: Path | str) -> tuple[bool, str | None]:
    """Validate a file path."""
    path = Path(path)

    if not path.exists():
        return False, f"Path does not exist: {path}"

    if not path.is_file():
        return False, f"Path is not a file: {path}"

    return True, None


def validate_config_keys(
    config: dict,
    required_keys: list[str],
    optional_keys: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Validate that a config has required keys."""
    errors = []
    missing = []

    for key in required_keys:
        if key not in config:
            errors.append(f"Missing required key: {key}")
            missing.append(key)

    if optional_keys:
        unknown = set(config.keys()) - set(required_keys) - set(optional_keys)
        if unknown:
            errors.append(f"Unknown keys: {', '.join(sorted(unknown))}")

    return len(missing) == 0, errors


def validate_json(data: str) -> tuple[bool, str | None]:
    """Validate JSON string."""
    try:
        json.loads(data)
        return True, None
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"


def sanitize_path(path: str) -> str:
    """Sanitize a path to prevent directory traversal."""
    # Remove leading/trailing whitespace
    path = path.strip()

    # Remove null bytes
    path = path.replace("\0", "")

    # Normalize separators
    path = path.replace("\\", "/")

    # Remove leading/trailing slashes
    path = path.strip("/")

    # Check for parent directory traversal
    if ".." in path:
        path = re.sub(r"\.+/", "", path)

    return path


# ============================================================================
# Hook Utilities
# ============================================================================

def create_hook_result(
    success: bool,
    message: str,
    data: Any = None,
    errors: list[str] | None = None,
) -> OperationResult:
    """Create a standardized hook operation result."""
    return OperationResult(
        success=success,
        message=message,
        data=data,
        errors=errors or [],
    )


def format_duration(ms: float) -> str:
    """Format duration in milliseconds to human-readable string."""
    if ms < 1:
        return f"{ms:.2f}ms"
    elif ms < 1000:
        return f"{ms:.1f}ms"
    elif ms < 60000:
        return f"{ms / 1000:.2f}s"
    else:
        return f"{ms / 60000:.2f}m"


def get_hook_metrics() -> dict[str, Any]:
    """Get current hook system metrics."""
    return {
        "python_version": sys.version,
        "platform": sys.platform,
        "working_directory": str(Path.cwd()),
        "environment": {
            k: v for k, v in os.environ.items()
            if not k.startswith("_") and not any(
                sensitive in k.lower()
                for sensitive in ("key", "token", "secret", "password")
            )
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ============================================================================
# Initialization
# ============================================================================

def setup_hook_environment(
    repo_root: Path | None = None,
    config_dir: str = ".claude",
    log_level: LogLevel = LogLevel.INFO,
) -> HookContext:
    """Set up the hook environment and return context."""
    if repo_root is None:
        repo_root = get_project_root()

    config_path = repo_root / config_dir

    logger = SimpleLogger(name="hooks", level=log_level)
    if logger._file is None:
        log_file = config_path / "hooks.log"
        if log_file.parent.exists():
            try:
                logger = SimpleLogger(name="hooks", level=log_level, file_path=log_file)
            except (OSError, PermissionError):
                pass

    return HookContext(
        hook_name="unknown",
        repo_root=repo_root,
        working_dir=Path.cwd(),
        config_dir=config_path,
        environment=os.getenv("ENVIRONMENT", "development"),
        dry_run=os.getenv("DRY_RUN", "").lower() in ("1", "true", "yes"),
        verbose=os.getenv("VERBOSE", "").lower() in ("1", "true", "yes"),
    )


# ============================================================================
# CLI Entry Point
# ============================================================================

def main() -> None:
    """CLI for testing integration utilities."""
    import argparse

    parser = argparse.ArgumentParser(description="Integration Utilities CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # File checksum command
    subparsers.add_parser("checksum", help="Calculate file checksum")
    parser.add_argument("--path", type=str, help="Path for checksum")
    parser.add_argument("--algorithm", default="sha256", help="Hash algorithm")

    # Git status command
    subparsers.add_parser("git-status", help="Show git status")

    # Config find command
    subparsers.add_parser("find-config", help="Find config files")
    parser.add_argument("--name", default="config.json", help="Config name")

    args = parser.parse_args()

    if args.command == "checksum" and args.path:
        checksum = file_checksum(args.path, args.algorithm)
        print(f"{args.algorithm.upper()}: {checksum}")

    elif args.command == "git-status":
        if is_git_repo():
            print(f"Git root: {get_git_root()}")
            print(f"Branch: {get_current_branch()}")
            print(f"Changed files: {get_changed_files()}")
        else:
            print("Not a git repository")

    elif args.command == "find-config":
        config = find_config_file(args.name)
        print(f"Found: {config}" if config else "Not found")

    else:
        print("Integration utilities ready")
        print(f"Project root: {get_project_root()}")
        print(f"Python: {sys.version.split()[0]}")


if __name__ == "__main__":
    main()
