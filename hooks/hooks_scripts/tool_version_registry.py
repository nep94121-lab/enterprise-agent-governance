"""
Tool Version Registry

Tracks tool versions, checks compatibility, and detects changes across the system.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Version:
    """Represents a version with major, minor, patch, and optional prerelease."""
    major: int = 0
    minor: int = 0
    patch: int = 0
    prerelease: str | None = None

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += f"-{self.prerelease}"
        return base

    @classmethod
    def parse(cls, version_str: str) -> Version:
        """Parse a version string into a Version object."""
        import re
        match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$', version_str)
        if not match:
            raise ValueError(f"Invalid version string: {version_str}")

        major = int(match.group(1))
        minor = int(match.group(2)) if match.group(2) else 0
        patch = int(match.group(3)) if match.group(3) else 0
        prerelease = match.group(4)

        return cls(major=major, minor=minor, patch=patch, prerelease=prerelease)

    def compare(self, other: Version) -> int:
        """Compare versions. Returns -1, 0, or 1."""
        self_tuple = (self.major, self.minor, self.patch)
        other_tuple = (other.major, other.minor, other.patch)

        if self_tuple < other_tuple:
            return -1
        elif self_tuple > other_tuple:
            return 1
        elif self.prerelease and not other.prerelease:
            return -1
        elif not self.prerelease and other.prerelease:
            return 1
        elif self.prerelease and other.prerelease:
            return -1 if self.prerelease < other.prerelease else (1 if self.prerelease > other.prerelease else 0)
        return 0

    def __lt__(self, other: Version) -> bool:
        return self.compare(other) < 0

    def __le__(self, other: Version) -> bool:
        return self.compare(other) <= 0

    def __gt__(self, other: Version) -> bool:
        return self.compare(other) > 0

    def __ge__(self, other: Version) -> bool:
        return self.compare(other) >= 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return False
        return self.compare(other) == 0


@dataclass
class CompatibilityRequirement:
    """Defines version compatibility requirements for a tool."""
    min_version: Version | None = None
    max_version: Version | None = None
    exact_version: Version | None = None
    allowed_versions: list[Version] = field(default_factory=list)

    def is_compatible(self, version: Version) -> bool:
        """Check if a version satisfies this compatibility requirement."""
        if self.exact_version is not None:
            return version == self.exact_version

        if self.min_version is not None and version < self.min_version:
            return False

        if self.max_version is not None and version > self.max_version:
            return False

        if self.allowed_versions and version not in self.allowed_versions:
            return False

        return True


@dataclass
class ToolInfo:
    """Information about a registered tool."""
    name: str
    current_version: Version
    previous_version: Version | None = None
    installed_path: str | None = None
    checksum: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    compatibility: CompatibilityRequirement | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            'name': self.name,
            'current_version': str(self.current_version),
            'previous_version': str(self.previous_version) if self.previous_version else None,
            'installed_path': self.installed_path,
            'checksum': self.checksum,
            'metadata': self.metadata,
            'last_updated': self.last_updated,
        }
        if self.compatibility:
            result['compatibility'] = {
                'min_version': str(self.compatibility.min_version) if self.compatibility.min_version else None,
                'max_version': str(self.compatibility.max_version) if self.compatibility.max_version else None,
                'exact_version': str(self.compatibility.exact_version) if self.compatibility.exact_version else None,
                'allowed_versions': [str(v) for v in self.compatibility.allowed_versions],
            }
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolInfo:
        compat_data = data.get('compatibility')
        compatibility = None
        if compat_data:
            compatibility = CompatibilityRequirement(
                min_version=Version.parse(compat_data['min_version']) if compat_data.get('min_version') else None,
                max_version=Version.parse(compat_data['max_version']) if compat_data.get('max_version') else None,
                exact_version=Version.parse(compat_data['exact_version']) if compat_data.get('exact_version') else None,
                allowed_versions=[Version.parse(v) for v in compat_data.get('allowed_versions', [])],
            )

        return cls(
            name=data['name'],
            current_version=Version.parse(data['current_version']),
            previous_version=Version.parse(data['previous_version']) if data.get('previous_version') else None,
            installed_path=data.get('installed_path'),
            checksum=data.get('checksum'),
            metadata=data.get('metadata', {}),
            last_updated=data.get('last_updated', datetime.now().isoformat()),
            compatibility=compatibility,
        )


@dataclass
class Change:
    """Represents a detected change in a tool."""
    tool_name: str
    change_type: str  # 'version_bump', 'installation', 'removal', 'checksum_mismatch'
    old_value: Any | None = None
    new_value: Any | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            'tool_name': self.tool_name,
            'change_type': self.change_type,
            'old_value': str(self.old_value) if self.old_value is not None else None,
            'new_value': str(self.new_value) if self.new_value is not None else None,
            'timestamp': self.timestamp,
        }


class ToolVersionRegistry:
    """Registry for tracking tool versions and detecting changes."""

    def __init__(self, registry_path: str | Path | None = None):
        self.registry_path = Path(registry_path) if registry_path else Path.home() / '.tool_version_registry.json'
        self._tools: dict[str, ToolInfo] = {}
        self._change_history: list[Change] = []
        self._load()

    def _load(self) -> None:
        """Load registry from disk."""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._tools = {
                        name: ToolInfo.from_dict(info)
                        for name, info in data.get('tools', {}).items()
                    }
                    self._change_history = [
                        Change(**c) for c in data.get('change_history', [])
                    ]
            except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as e:
                print(f"Warning: Failed to load registry: {e}", file=sys.stderr)
                self._tools = {}
                self._change_history = []

    def _save(self) -> None:
        """Save registry to disk."""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'tools': {name: info.to_dict() for name, info in self._tools.items()},
            'change_history': [c.to_dict() for c in self._change_history],
            'last_modified': datetime.now().isoformat(),
        }
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _hash_file(self, file_path: Path) -> str:
        """Compute SHA256 checksum of a file in chunks to prevent OOM."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError:
            return ''

    def _compute_checksum(self, path: str | Path) -> str:
        """Compute SHA256 checksum of a file or directory in chunks to prevent OOM."""
        path = Path(path)
        if not path.exists():
            return ''
        if path.is_file():
            return self._hash_file(path)
        elif path.is_dir():
            checksums = []
            for file_path in sorted(path.rglob('*')):
                if file_path.is_file():
                    checksums.append(self._hash_file(file_path))
            combined = ''.join(checksums)
            return hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return ''

    def register_tool(
        self,
        name: str,
        version: str | Version,
        installed_path: str | Path | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Change | None:
        """Register or update a tool in the registry."""
        version = version if isinstance(version, Version) else Version.parse(str(version))
        changes: list[Change] = []

        if name in self._tools:
            tool = self._tools[name]
            old_version = tool.current_version

            # Detect version change
            if version != old_version:
                changes.append(Change(
                    tool_name=name,
                    change_type='version_bump',
                    old_value=old_version,
                    new_value=version,
                ))
                tool.previous_version = old_version
                tool.current_version = version

            # Retain installed_path and checksum if not explicitly provided
            if installed_path is not None:
                installed_path_str = str(installed_path)
                tool.installed_path = installed_path_str
                if Path(installed_path_str).exists():
                    checksum = self._compute_checksum(installed_path_str)
                else:
                    checksum = None
            else:
                installed_path_str = tool.installed_path
                if installed_path_str and Path(installed_path_str).exists():
                    checksum = self._compute_checksum(installed_path_str)
                else:
                    checksum = tool.checksum

            # Detect checksum mismatch
            if checksum and tool.checksum and checksum != tool.checksum:
                changes.append(Change(
                    tool_name=name,
                    change_type='checksum_mismatch',
                    old_value=tool.checksum,
                    new_value=checksum,
                ))

            if checksum is not None:
                tool.checksum = checksum

            if metadata:
                tool.metadata.update(metadata)
            tool.last_updated = datetime.now().isoformat()
        else:
            # New tool registration
            installed_path_str = str(installed_path) if installed_path is not None else None
            checksum = None
            if installed_path_str and Path(installed_path_str).exists():
                checksum = self._compute_checksum(installed_path_str)

            change = Change(
                tool_name=name,
                change_type='installation',
                old_value=None,
                new_value=version,
            )
            changes.append(change)
            self._tools[name] = ToolInfo(
                name=name,
                current_version=version,
                installed_path=installed_path_str,
                checksum=checksum,
                metadata=metadata or {},
            )

        for ch in changes:
            self._change_history.append(ch)

        # Keep only last 1000 changes
        if len(self._change_history) > 1000:
            self._change_history = self._change_history[-1000:]

        self._save()
        return changes[0] if changes else None

    def unregister_tool(self, name: str) -> Change | None:
        """Remove a tool from the registry."""
        if name not in self._tools:
            return None

        tool = self._tools[name]
        change = Change(
            tool_name=name,
            change_type='removal',
            old_value=tool.current_version,
            new_value=None,
        )

        del self._tools[name]
        self._change_history.append(change)
        if len(self._change_history) > 1000:
            self._change_history = self._change_history[-1000:]
        self._save()
        return change

    def get_tool(self, name: str) -> ToolInfo | None:
        """Get information about a registered tool."""
        return self._tools.get(name)

    def get_version(self, name: str) -> Version | None:
        """Get the current version of a tool."""
        tool = self._tools.get(name)
        return tool.current_version if tool else None

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def list_changes(self, limit: int = 100) -> list[Change]:
        """Get recent change history."""
        return self._change_history[-limit:]

    def get_changes_for_tool(self, name: str) -> list[Change]:
        """Get all changes for a specific tool."""
        return [c for c in self._change_history if c.tool_name == name]

    def set_compatibility_requirement(
        self,
        name: str,
        min_version: str | Version | None = None,
        max_version: str | Version | None = None,
        exact_version: str | Version | None = None,
    ) -> bool:
        """Set compatibility requirements for a tool."""
        if name not in self._tools:
            return False

        self._tools[name].compatibility = CompatibilityRequirement(
            min_version=Version.parse(str(min_version)) if min_version else None,
            max_version=Version.parse(str(max_version)) if max_version else None,
            exact_version=Version.parse(str(exact_version)) if exact_version else None,
        )
        self._save()
        return True

    def check_compatibility(self, name: str, version: str | Version | None = None) -> tuple[bool, str | None]:
        """Check if a tool version is compatible with its requirements."""
        tool = self._tools.get(name)
        if not tool:
            return False, f"Tool '{name}' not found in registry"

        if not tool.compatibility:
            return True, None

        check_version = Version.parse(str(version)) if version else tool.current_version

        if tool.compatibility.is_compatible(check_version):
            return True, None
        else:
            return False, f"Version {check_version} does not meet compatibility requirements"

    def check_for_changes(self, name: str, current_version: str | Version) -> list[Change]:
        """Check if a tool has changed since last registration."""
        changes = []
        tool = self._tools.get(name)
        current_version = Version.parse(str(current_version)) if isinstance(current_version, str) else current_version

        if not tool:
            changes.append(Change(
                tool_name=name,
                change_type='installation',
                old_value=None,
                new_value=current_version,
            ))
        else:
            if current_version != tool.current_version:
                changes.append(Change(
                    tool_name=name,
                    change_type='version_bump',
                    old_value=tool.current_version,
                    new_value=current_version,
                ))

        return changes

    def detect_all_changes(self, tools: dict[str, str | Version]) -> dict[str, list[Change]]:
        """Detect changes across multiple tools at once."""
        results = {}
        for name, version in tools.items():
            changes = self.check_for_changes(name, version)
            if changes:
                results[name] = changes
        return results

    def export_registry(self) -> dict[str, Any]:
        """Export the full registry as a dictionary."""
        return {
            'tools': {name: info.to_dict() for name, info in self._tools.items()},
            'change_history': [c.to_dict() for c in self._change_history],
            'exported_at': datetime.now().isoformat(),
        }

    def import_registry(self, data: dict[str, Any]) -> int:
        """Import tools from a dictionary. Returns count of imported tools."""
        count = 0
        for name, info in data.get('tools', {}).items():
            try:
                self._tools[name] = ToolInfo.from_dict(info)
                count += 1
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping tool '{name}' due to error: {e}", file=sys.stderr)
        self._save()
        return count

    def get_outdated_tools(self, current_versions: dict[str, str | Version]) -> dict[str, tuple[Version, Version]]:
        """Find tools where the current version is different from registered version."""
        outdated = {}
        for name, current in current_versions.items():
            current = Version.parse(str(current)) if isinstance(current, str) else current
            registered = self.get_version(name)
            if registered and current != registered:
                outdated[name] = (registered, current)
        return outdated

    def clear_history(self) -> None:
        """Clear change history (keeps tool registrations)."""
        self._change_history = []
        self._save()

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __repr__(self) -> str:
        return f"ToolVersionRegistry(tools={len(self._tools)}, changes={len(self._change_history)})"


def get_registry(registry_path: str | Path | None = None) -> ToolVersionRegistry:
    """Get or create a ToolVersionRegistry instance."""
    return ToolVersionRegistry(registry_path)


if __name__ == '__main__':
    registry = ToolVersionRegistry()
    registry.register_tool('mytool', '1.0.0', metadata={'author': 'demo'})
    registry.register_tool('other-tool', '2.3.1')
    change = registry.register_tool('mytool', '1.1.0')
    if change:
        print(f"Detected change: {change.change_type} for {change.tool_name}")
    registry.set_compatibility_requirement('mytool', min_version='1.0.0', max_version='2.0.0')
    compatible, msg = registry.check_compatibility('mytool', '1.5.0')
    print(f"Compatible: {compatible}, Message: {msg}")
    print(f"Registered tools: {registry.list_tools()}")
    tool = registry.get_tool('mytool')
    if tool:
        print(f"mytool version: {tool.current_version}")
    print(f"Recent changes: {registry.list_changes()}")