"""MCP Tool Registry and Auto-Discovery System.

This module provides a centralized registry for MCP (Model Context Protocol) tools,
with auto-discovery capabilities, versioning, and health monitoring.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import logging
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Enumeration of possible tool states."""
    DISCOVERED = "discovered"
    REGISTERED = "registered"
    INITIALIZED = "initialized"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DEPRECATED = "deprecated"


class ToolCapability(Enum):
    """Tool capability categories."""
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    DATABASE = "database"
    COMPUTATION = "computation"
    MEMORY = "memory"
    EXTERNAL_API = "external_api"
    CODE_EXECUTION = "code_execution"
    ORCHESTRATION = "orchestration"


@dataclass
class ToolVersion:
    """Represents a tool version with metadata."""
    major: int = 1
    minor: int = 0
    patch: int = 0
    prerelease: str | None = None

    def __str__(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        return version

    def __lt__(self, other: ToolVersion) -> bool:
        """Compare versions for ordering."""
        if not isinstance(other, ToolVersion):
            return NotImplemented
        self_tuple = (self.major, self.minor, self.patch, self.prerelease or "z")
        other_tuple = (other.major, other.minor, other.patch, other.prerelease or "z")
        return self_tuple < other_tuple

    def __le__(self, other: ToolVersion) -> bool:
        if not isinstance(other, ToolVersion):
            return NotImplemented
        return self < other or self == other

    def __gt__(self, other: ToolVersion) -> bool:
        if not isinstance(other, ToolVersion):
            return NotImplemented
        return not (self <= other)

    def __ge__(self, other: ToolVersion) -> bool:
        if not isinstance(other, ToolVersion):
            return NotImplemented
        return not (self < other)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ToolVersion):
            return False
        return (self.major == other.major and
                self.minor == other.minor and
                self.patch == other.patch and
                self.prerelease == other.prerelease)

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.prerelease))

    @classmethod
    def from_string(cls, version_str: str) -> ToolVersion:
        """Parse version from string like '1.2.3-beta'."""
        import re
        match = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?", version_str)
        if not match:
            raise ValueError(f"Invalid version string: {version_str}")
        major, minor, patch, prerelease = match.groups()
        return cls(
            major=int(major),
            minor=int(minor),
            patch=int(patch),
            prerelease=prerelease
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": self.prerelease,
            "string": str(self)
        }


@dataclass
class ToolMetadata:
    """Metadata about a registered tool."""
    name: str
    description: str
    version: ToolVersion
    author: str | None = None
    tags: list[str] = field(default_factory=list)
    capabilities: list[ToolCapability] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] | None = None
    examples: list[dict[str, str]] = field(default_factory=list)
    deprecation_message: str | None = None
    replaced_by: str | None = None


@dataclass
class MCPTool:
    """Represents a registered MCP tool."""
    name: str
    func: Callable[..., Any]
    metadata: ToolMetadata
    status: ToolStatus = ToolStatus.DISCOVERED
    registered_at: datetime = field(default_factory=datetime.now)
    last_invoked: datetime | None = None
    invocation_count: int = 0
    error_count: int = 0
    average_latency_ms: float = 0.0
    health_check_enabled: bool = True
    custom_config: dict[str, Any] = field(default_factory=dict)
    _total_latency_ms: float = field(default=0.0, init=False, repr=False)
    _latency_count: int = field(default=0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    async def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Invoke the tool with timing and error tracking (coroutine-aware)."""
        start_time = datetime.now()
        start_perf = time.perf_counter()
        self.last_invoked = start_time
        with self._lock:
            self.invocation_count += 1

        try:
            if inspect.iscoroutinefunction(self.func):
                result = await self.func(*args, **kwargs)
            else:
                result = self.func(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
            return result
        except Exception as e:
            with self._lock:
                self.error_count += 1
            logger.error(f"Tool {self.name} invocation failed: {e}")
            raise
        finally:
            elapsed = (time.perf_counter() - start_perf) * 1000.0
            with self._lock:
                self._latency_count += 1
                self._total_latency_ms += elapsed
                self.average_latency_ms = self._total_latency_ms / self._latency_count

    def invoke_sync(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronously invoke a tool if func is not an async coroutine."""
        if inspect.iscoroutinefunction(self.func):
            raise TypeError(
                f"Tool '{self.name}' is an async coroutine function and must be awaited using 'await tool.invoke(...)'"
            )
        start_time = datetime.now()
        start_perf = time.perf_counter()
        self.last_invoked = start_time
        with self._lock:
            self.invocation_count += 1

        try:
            result = self.func(*args, **kwargs)
            if inspect.isawaitable(result):
                raise TypeError(
                    f"Tool '{self.name}' returned an awaitable and must be awaited using 'await tool.invoke(...)'"
                )
            return result
        except Exception as e:
            with self._lock:
                self.error_count += 1
            logger.error(f"Tool {self.name} invocation failed: {e}")
            raise
        finally:
            elapsed = (time.perf_counter() - start_perf) * 1000.0
            with self._lock:
                self._latency_count += 1
                self._total_latency_ms += elapsed
                self.average_latency_ms = self._total_latency_ms / self._latency_count


class ToolRegistry:
    """Central registry for MCP tools with auto-discovery."""

    _instance: ToolRegistry | None = None

    def __new__(cls) -> ToolRegistry:
        """Singleton pattern for global registry."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        self._tools: dict[str, MCPTool] = {}
        self._discovery_paths: list[Path] = []
        self._discovery_patterns: list[str] = ["*_tool.py", "*_tools.py", "tool_*.py"]
        self._discovered_modules: list[str] = []
        self._last_discovery: datetime | None = None
        self._discovery_lock = asyncio.Lock()

        # Tool category index for fast lookup
        self._capability_index: dict[ToolCapability, list[str]] = {
            cap: [] for cap in ToolCapability
        }
        self._tag_index: dict[str, list[str]] = {}

        logger.info("MCP Tool Registry initialized")

    @classmethod
    def get_instance(cls) -> ToolRegistry:
        """Get the singleton registry instance."""
        return cls()

    def register_tool(
        self,
        name: str,
        func: Callable[..., Any],
        metadata: ToolMetadata,
        **config: Any
    ) -> MCPTool:
        """Register a tool with the registry."""
        tool = MCPTool(
            name=name,
            func=func,
            metadata=metadata,
            custom_config=config,
            status=ToolStatus.REGISTERED
        )

        self._tools[name] = tool
        self._update_indices(tool)

        logger.info(f"Registered tool: {name} v{metadata.version}")
        return tool

    def _update_indices(self, tool: MCPTool) -> None:
        """Update search indices for a tool."""
        # Capability index
        for cap in tool.metadata.capabilities:
            if tool.name not in self._capability_index[cap]:
                self._capability_index[cap].append(tool.name)

        # Tag index
        for tag in tool.metadata.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = []
            if tool.name not in self._tag_index[tag]:
                self._tag_index[tag].append(tool.name)

    def get_tool(self, name: str) -> MCPTool | None:
        """Retrieve a tool by name."""
        return self._tools.get(name)

    def get_all_tools(self) -> list[MCPTool]:
        """Get all registered tools."""
        return list(self._tools.values())

    def get_tools_by_capability(self, capability: ToolCapability) -> list[MCPTool]:
        """Get tools that match a specific capability."""
        tool_names = self._capability_index.get(capability, [])
        return [self._tools[name] for name in tool_names if name in self._tools]

    def get_tools_by_tag(self, tag: str) -> list[MCPTool]:
        """Get tools matching a tag."""
        tool_names = self._tag_index.get(tag, [])
        return [self._tools[name] for name in tool_names if name in self._tools]

    def get_tools_by_status(self, status: ToolStatus) -> list[MCPTool]:
        """Get tools with a specific status."""
        return [tool for tool in self._tools.values() if tool.status == status]

    def get_healthy_tools(self) -> list[MCPTool]:
        """Get all tools in healthy status."""
        return self.get_tools_by_status(ToolStatus.HEALTHY)

    def add_discovery_path(self, path: str | Path) -> None:
        """Add a directory path for tool auto-discovery."""
        path_obj = Path(path) if isinstance(path, str) else path
        if path_obj not in self._discovery_paths:
            self._discovery_paths.append(path_obj)
            logger.info(f"Added discovery path: {path_obj}")

    def remove_discovery_path(self, path: str | Path) -> None:
        """Remove a directory path from discovery."""
        path_obj = Path(path) if isinstance(path, str) else path
        if path_obj in self._discovery_paths:
            self._discovery_paths.remove(path_obj)
            logger.info(f"Removed discovery path: {path_obj}")

    async def discover_tools(
        self,
        paths: list[Path] | None = None,
        force: bool = False
    ) -> list[str]:
        """Auto-discover tools from configured paths."""
        async with self._discovery_lock:
            if self._last_discovery and not force:
                logger.info(f"Returning cached discovery results ({len(self._discovered_modules)} modules)")
                return list(self._discovered_modules)

            paths_to_search = paths or self._discovery_paths
            discovered = []

            for base_path in paths_to_search:
                if not base_path.exists():
                    logger.warning(f"Discovery path does not exist: {base_path}")
                    continue

                discovered.extend(await self._discover_in_path(base_path))

            self._discovered_modules = discovered
            self._last_discovery = datetime.now()

            logger.info(f"Discovered {len(discovered)} modules")
            return discovered

    async def _discover_in_path(self, base_path: Path) -> list[str]:
        """Discover tool modules within a path."""
        discovered = []

        # P1 Fix: Ensure base_path is in sys.path so modules relative to base_path can be imported
        base_resolved = base_path.resolve()
        base_str = str(base_resolved)
        if base_str not in sys.path:
            sys.path.insert(0, base_str)

        # Also add parent directory if base_path is a Python package
        parent_str = str(base_resolved.parent)
        if (base_resolved / "__init__.py").exists() and parent_str not in sys.path:
            sys.path.insert(0, parent_str)

        for pattern in self._discovery_patterns:
            for module_path in base_path.rglob(pattern):
                if module_path.is_file() and module_path.name != "__init__.py":
                    module_name = self._path_to_module_name(module_path, base_path)
                    try:
                        await self._import_and_register_module(module_name, module_path)
                        discovered.append(module_name)
                    except Exception as e:
                        logger.error(f"Failed to import {module_name}: {e}")

        return discovered

    def _is_defined_in_module(self, attr: Any, module: Any) -> bool:
        """Check if an attribute was defined within the module itself, not imported from outside."""
        target = attr
        while hasattr(target, "__wrapped__"):
            target = target.__wrapped__
        target = getattr(target, "func", target)

        attr_mod = getattr(target, "__module__", getattr(attr, "__module__", None))
        if attr_mod is not None:
            return attr_mod == module.__name__

        try:
            mod = inspect.getmodule(target) or inspect.getmodule(attr)
            if mod is not None:
                return mod is module or mod.__name__ == module.__name__
        except Exception:
            pass

        try:
            target_code = getattr(target, "__code__", getattr(attr, "__code__", None))
            if target_code and hasattr(module, "__file__") and module.__file__:
                return Path(target_code.co_filename).resolve() == Path(module.__file__).resolve()
        except Exception:
            pass

        return False

    def _path_to_module_name(self, path: Path, base_path: Path) -> str:
        """Convert file path to Python module name."""
        try:
            rel_path = path.resolve().relative_to(base_path.resolve())
        except ValueError:
            rel_path = path.relative_to(base_path)
        parts = list(rel_path.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        elif parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]  # Remove .py extension
        return ".".join(parts)

    async def _import_and_register_module(
        self,
        module_name: str,
        module_path: Path | None = None,
    ) -> None:
        """Import a module and register any discovered tools."""
        try:
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                if module_path and module_path.is_file():
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = module
                        spec.loader.exec_module(module)
                    else:
                        raise
                else:
                    raise

            # Look for tool registration patterns
            for attr_name in dir(module):
                if attr_name.startswith("__"):
                    continue

                attr = getattr(module, attr_name, None)
                if attr is None:
                    continue

                # Filter: skip attributes imported from other modules to prevent crash or accidental re-registration
                if not self._is_defined_in_module(attr, module):
                    continue

                # Check for explicitly decorated @register tools
                if hasattr(attr, "_mcp_tool_metadata") and isinstance(attr._mcp_tool_metadata, ToolMetadata):
                    self.register_tool(attr._mcp_tool_metadata.name, attr, attr._mcp_tool_metadata)

                # Check for @tool decorator patterns (langchain, etc.)
                elif callable(attr) and hasattr(attr, "name") and hasattr(attr, "description"):
                    await self._register_decorated_tool(attr_name, attr, module_name)

                # Check for explicit registration functions (sync or async)
                elif attr_name.startswith("register_") and callable(attr):
                    try:
                        sig = inspect.signature(attr)
                        params = list(sig.parameters.values())
                        required_params = [
                            p for p in params
                            if p.default == inspect.Parameter.empty
                            and p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                        ]
                        if len(required_params) > 1:
                            continue
                        takes_arg = len(params) > 0
                    except (ValueError, TypeError):
                        takes_arg = True

                    try:
                        if inspect.iscoroutinefunction(attr):
                            if takes_arg:
                                await attr(self)
                            else:
                                await attr()
                        else:
                            if takes_arg:
                                res = attr(self)
                            else:
                                res = attr()
                            if inspect.isawaitable(res):
                                await res
                    except Exception as reg_err:
                        logger.warning(f"Error executing registration function {attr_name} in {module_name}: {reg_err}")

        except ImportError as e:
            logger.error(f"Import error for {module_name}: {e}")
            raise

    async def _register_decorated_tool(
        self,
        name: str,
        tool_func: Any,
        source_module: str
    ) -> None:
        """Register a tool that was decorated with @tool."""
        metadata = ToolMetadata(
            name=name,
            description=getattr(tool_func, "description", f"Auto-discovered tool from {source_module}"),
            version=ToolVersion(1, 0, 0),
            tags=["auto-discovered"]
        )

        self.register_tool(name, tool_func, metadata)

    def unregister_tool(self, name: str) -> bool:
        """Unregister a tool by name."""
        if name in self._tools:
            tool = self._tools[name]

            # Clean up indices
            for cap in tool.metadata.capabilities:
                if name in self._capability_index.get(cap, []):
                    self._capability_index[cap].remove(name)

            for tag in tool.metadata.tags:
                if tag in self._tag_index and name in self._tag_index[tag]:
                    self._tag_index[tag].remove(name)

            del self._tools[name]
            logger.info(f"Unregistered tool: {name}")
            return True
        return False

    def update_tool_status(self, name: str, status: ToolStatus) -> bool:
        """Update the status of a tool."""
        tool = self._tools.get(name)
        if tool:
            tool.status = status
            logger.info(f"Tool {name} status updated to {status.value}")
            return True
        return False

    def get_availability_matrix(self) -> dict[str, dict[str, Any]]:
        """Generate tool availability matrix."""
        matrix = {}
        for name, tool in self._tools.items():
            matrix[name] = {
                "status": tool.status.value,
                "healthy": tool.status == ToolStatus.HEALTHY,
                "version": str(tool.metadata.version),
                "capabilities": [c.value for c in tool.metadata.capabilities],
                "last_invoked": tool.last_invoked.isoformat() if tool.last_invoked else None,
                "invocation_count": tool.invocation_count,
                "error_count": tool.error_count,
                "error_rate": tool.error_count / tool.invocation_count if tool.invocation_count > 0 else 0,
                "average_latency_ms": tool.average_latency_ms,
                "registered_at": tool.registered_at.isoformat(),
                "health_check_enabled": tool.health_check_enabled,
                "deprecated": tool.status == ToolStatus.DEPRECATED,
                "replaced_by": tool.metadata.replaced_by,
            }
        return matrix

    def get_registry_stats(self) -> dict[str, Any]:
        """Get registry statistics."""
        total = len(self._tools)
        by_status = {}
        by_capability = {}

        for tool in self._tools.values():
            status_key = tool.status.value
            by_status[status_key] = by_status.get(status_key, 0) + 1

            for cap in tool.metadata.capabilities:
                cap_key = cap.value
                by_capability[cap_key] = by_capability.get(cap_key, 0) + 1

        return {
            "total_tools": total,
            "discovery_paths": [str(p) for p in self._discovery_paths],
            "last_discovery": self._last_discovery.isoformat() if self._last_discovery else None,
            "tools_by_status": by_status,
            "tools_by_capability": by_capability,
            "total_invocations": sum(t.invocation_count for t in self._tools.values()),
            "total_errors": sum(t.error_count for t in self._tools.values()),
        }

    def export_registry(self) -> dict[str, Any]:
        """Export full registry state for serialization."""
        return {
            "exported_at": datetime.now().isoformat(),
            "tools": {
                name: {
                    "name": tool.name,
                    "metadata": {
                        "name": tool.metadata.name,
                        "description": tool.metadata.description,
                        "version": tool.metadata.version.to_dict(),
                        "author": tool.metadata.author,
                        "tags": tool.metadata.tags,
                        "capabilities": [c.value for c in tool.metadata.capabilities],
                        "dependencies": tool.metadata.dependencies,
                    },
                    "status": tool.status.value,
                    "registered_at": tool.registered_at.isoformat(),
                    "last_invoked": tool.last_invoked.isoformat() if tool.last_invoked else None,
                    "invocation_count": tool.invocation_count,
                    "error_count": tool.error_count,
                    "average_latency_ms": tool.average_latency_ms,
                    "custom_config": tool.custom_config,
                }
                for name, tool in self._tools.items()
            },
            "stats": self.get_registry_stats()
        }


def register(
    name: str,
    description: str = "",
    version: str | ToolVersion = "1.0.0",
    author: str | None = None,
    tags: list[str] | None = None,
    capabilities: list[ToolCapability] | None = None,
    dependencies: list[str] | None = None,
) -> Callable:
    """Decorator to register a function as an MCP tool."""
    def decorator(func: Callable) -> Callable:
        metadata = ToolMetadata(
            name=name,
            description=description,
            version=ToolVersion.from_string(version) if isinstance(version, str) else version,
            author=author,
            tags=tags or [],
            capabilities=capabilities or [],
            dependencies=dependencies or [],
        )

        func._mcp_tool_metadata = metadata

        registry = ToolRegistry.get_instance()
        registry.register_tool(name, func, metadata)

        return func
    return decorator


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    return ToolRegistry.get_instance()


def register_tool(
    func: Callable,
    name: str | None = None,
    description: str = "",
    version: str = "1.0.0",
    **kwargs: Any
) -> MCPTool:
    """Register a function as an MCP tool."""
    tool_name = name or func.__name__
    metadata = ToolMetadata(
        name=tool_name,
        description=description or func.__doc__ or "",
        version=ToolVersion.from_string(version),
        **kwargs
    )

    registry = ToolRegistry.get_instance()
    return registry.register_tool(tool_name, func, metadata)
