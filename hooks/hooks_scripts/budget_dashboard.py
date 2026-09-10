#!/usr/bin/env python3
"""
Budget Dashboard for Multi-Agent Token Management.

Real-time terminal dashboard displaying token usage, per-role visualization,
warning indicators, and ANSI-colored output.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


# ANSI Color Codes
class AnsiColors:
    """ANSI color and style codes for terminal output."""
    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    DEFAULT = "\033[39m"

    # Bright foreground colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    BG_DEFAULT = "\033[49m"

    # Status-specific colors
    OK = BRIGHT_GREEN
    WARNING = BRIGHT_YELLOW
    ERROR = BRIGHT_RED
    INFO = BRIGHT_CYAN
    MUTED = BRIGHT_BLACK

    @classmethod
    def clear_screen(cls) -> str:
        """Return escape sequence to clear screen."""
        return "\033[2J\033[H"

    @classmethod
    def cursor_home(cls) -> str:
        """Return escape sequence to move cursor to home position."""
        return "\033[H"

    @classmethod
    def hide_cursor(cls) -> str:
        """Hide terminal cursor."""
        return "\033[?25l"

    @classmethod
    def show_cursor(cls) -> str:
        """Show terminal cursor."""
        return "\033[?25h"

    @classmethod
    def save_cursor(cls) -> str:
        """Save current cursor position."""
        return "\033[s"

    @classmethod
    def restore_cursor(cls) -> str:
        """Restore saved cursor position."""
        return "\033[u"


class StatusLevel(Enum):
    """Status level for budget indicators."""
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"
    EXHAUSTED = "exhausted"


@dataclass
class BudgetEntry:
    """Single budget tracking entry."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    role: str = ""
    tokens: int = 0
    token_type: str = "prompt"
    cumulative: int = 0


@dataclass
class RoleBudgetDisplay:
    """Display data for a single role."""
    role: str
    role_display: str
    budget: int
    used: int
    remaining: int
    percentage: float
    status: StatusLevel
    warning_threshold: float = 0.80
    critical_threshold: float = 0.95
    history: list[int] = field(default_factory=list)


class BudgetDashboard:
    """
    Real-time terminal dashboard for token budget monitoring.

    Features:
    - Real-time token usage display with auto-refresh
    - Per-role visualization with progress bars
    - Warning/critical/exhausted status indicators
    - ANSI-colored terminal output
    - Thread-safe updates
    - Optional CSV export
    """

    # Bar characters
    BAR_FULL = "█"
    BAR_EMPTY = "░"
    BAR_HALF = "▓"
    ARROW_UP = "▲"
    ARROW_DOWN = "▼"
    ARROW_RIGHT = "►"

    # Width settings
    DEFAULT_WIDTH = 80
    ROLE_WIDTH = 8
    BUDGET_WIDTH = 12
    PERCENT_WIDTH = 8

    def __init__(
        self,
        budgets: dict[str, int] | None = None,
        warning_threshold: float = 0.80,
        critical_threshold: float = 0.95,
        refresh_interval: float = 1.0,
        output_width: int = DEFAULT_WIDTH,
        show_history: bool = True,
        history_length: int = 30,
        use_colors: bool = True,
    ):
        """
        Initialize the budget dashboard.

        Args:
            budgets: Budget limits per role (e.g., {"pm": 15000, "dev": 12000})
            warning_threshold: Percentage to trigger warning (default 0.80)
            critical_threshold: Percentage to trigger critical (default 0.95)
            refresh_interval: Seconds between display updates
            output_width: Terminal width for formatting
            show_history: Show usage history sparkline
            history_length: Number of history points to show
            use_colors: Enable ANSI color output
        """
        # Default budgets if not specified
        self._budgets = budgets or {
            "pm": 15000,
            "dev": 12000,
            "qa": 15000,
            "tl": 12000,
        }

        self._warning_threshold = warning_threshold
        self._critical_threshold = critical_threshold
        self._refresh_interval = refresh_interval
        self._output_width = output_width
        self._show_history = show_history
        self._history_length = history_length
        self._use_colors = use_colors

        # State
        self._role_data: dict[str, RoleBudgetDisplay] = {}
        self._usage_history: dict[str, list[int]] = {
            role: [] for role in self._budgets
        }
        self._lock = threading.RLock()
        self._running = False
        self._update_thread: threading.Thread | None = None
        self._last_update: datetime = datetime.now(UTC)

        # Initialize role displays
        for role, budget in self._budgets.items():
            self._role_data[role] = RoleBudgetDisplay(
                role=role,
                role_display=role.upper(),
                budget=budget,
                used=0,
                remaining=budget,
                percentage=0.0,
                status=StatusLevel.NORMAL,
                warning_threshold=warning_threshold,
                critical_threshold=critical_threshold,
            )

    def _color(self, color_code: str, text: str) -> str:
        """Apply color to text if colors are enabled."""
        if self._use_colors:
            return f"{color_code}{text}{AnsiColors.RESET}"
        return text

    def _get_status_color(self, status: StatusLevel) -> str:
        """Get color code for status level."""
        colors = {
            StatusLevel.NORMAL: AnsiColors.OK,
            StatusLevel.WARNING: AnsiColors.WARNING,
            StatusLevel.CRITICAL: AnsiColors.ERROR,
            StatusLevel.EXHAUSTED: AnsiColors.BRIGHT_MAGENTA,
        }
        return colors.get(status, AnsiColors.DEFAULT)

    def _get_status_icon(self, status: StatusLevel) -> str:
        """Get icon for status level."""
        icons = {
            StatusLevel.NORMAL: self._color(AnsiColors.OK, "●"),
            StatusLevel.WARNING: self._color(AnsiColors.WARNING, "⚠"),
            StatusLevel.CRITICAL: self._color(AnsiColors.ERROR, "▲"),
            StatusLevel.EXHAUSTED: self._color(AnsiColors.BRIGHT_MAGENTA, "✖"),
        }
        return icons.get(status, "○")

    def _calculate_status(self, percentage: float) -> StatusLevel:
        """Determine status level based on percentage."""
        if percentage >= 1.0:
            return StatusLevel.EXHAUSTED
        elif percentage >= self._critical_threshold:
            return StatusLevel.CRITICAL
        elif percentage >= self._warning_threshold:
            return StatusLevel.WARNING
        return StatusLevel.NORMAL

    def _format_number(self, num: int) -> str:
        """Format number with thousands separator."""
        return f"{num:,}"

    def _render_progress_bar(
        self,
        percentage: float,
        width: int = 20,
        status: StatusLevel = StatusLevel.NORMAL,
    ) -> str:
        """Render a progress bar."""
        filled = int(percentage * width)
        empty = width - filled

        color = self._get_status_color(status)
        bar = self._color(color, self.BAR_FULL * filled)
        bar += self._color(AnsiColors.MUTED, self.BAR_EMPTY * empty)

        return f"[{bar}]"

    def _render_sparkline(self, values: list[int], width: int = 15) -> str:
        """Render a sparkline from values."""
        if not values:
            return " " * width

        min_val = min(values) if values else 0
        max_val = max(values) if values else 1

        # Normalize values to 0-7 range (block characters)
        blocks = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        chars = []

        for val in values[-width:]:
            if max_val > min_val:
                normalized = int((val - min_val) / (max_val - min_val) * 7)
            else:
                normalized = 0
            chars.append(blocks[min(7, max(0, normalized))])

        # Pad to width
        while len(chars) < width:
            chars.insert(0, " ")

        return self._color(AnsiColors.INFO, "".join(chars))

    def update_role(
        self,
        role: str,
        tokens_used: int,
        token_type: str = "prompt",
    ) -> RoleBudgetDisplay:
        """
        Update token usage for a role.

        Args:
            role: Role name (e.g., "pm", "dev")
            tokens_used: Number of tokens to add
            token_type: Type of token (prompt, completion)

        Returns:
            Updated RoleBudgetDisplay
        """
        with self._lock:
            role_lower = role.lower()
            if role_lower not in self._role_data:
                # Add new role dynamically
                self._role_data[role_lower] = RoleBudgetDisplay(
                    role=role_lower,
                    role_display=role.upper(),
                    budget=self._budgets.get(role_lower, 15000),
                    used=0,
                    remaining=self._budgets.get(role_lower, 15000),
                    percentage=0.0,
                    status=StatusLevel.NORMAL,
                    warning_threshold=self._warning_threshold,
                    critical_threshold=self._critical_threshold,
                )
                self._usage_history[role_lower] = []

            display = self._role_data[role_lower]

            # Update usage
            display.used += tokens_used
            display.remaining = max(0, display.budget - display.used)
            display.percentage = display.used / display.budget if display.budget > 0 else 0
            display.status = self._calculate_status(display.percentage)
            self._last_update = datetime.now(UTC)

            # Update history
            self._usage_history[role_lower].append(display.used)
            if len(self._usage_history[role_lower]) > self._history_length:
                self._usage_history[role_lower] = self._usage_history[role_lower][-self._history_length:]
            display.history = list(self._usage_history[role_lower])

            self._last_update = datetime.now(UTC)

            return display

    def set_role_usage(
        self,
        role: str,
        used: int,
    ) -> RoleBudgetDisplay:
        '''
        Set absolute token usage for a role without accumulating.
        Prevents token explosion when syncing from an external counter.
        '''
        with self._lock:
            role_lower = role.lower()
            if role_lower not in self._role_data:
                self._role_data[role_lower] = RoleBudgetDisplay(
                    role=role_lower,
                    role_display=role.upper(),
                    budget=self._budgets.get(role_lower, 15000),
                    used=0,
                    remaining=self._budgets.get(role_lower, 15000),
                    percentage=0.0,
                    status=StatusLevel.NORMAL,
                    warning_threshold=self._warning_threshold,
                    critical_threshold=self._critical_threshold,
                )
                self._usage_history[role_lower] = []

            display = self._role_data[role_lower]
            display.used = max(0, used)
            display.remaining = max(0, display.budget - display.used)
            display.percentage = display.used / display.budget if display.budget > 0 else 0.0
            display.status = self._calculate_status(display.percentage)
            self._last_update = datetime.now(UTC)

            # Update history only if usage changed or history is empty
            if not self._usage_history[role_lower] or self._usage_history[role_lower][-1] != display.used:
                self._usage_history[role_lower].append(display.used)
                if len(self._usage_history[role_lower]) > self._history_length:
                    self._usage_history[role_lower] = self._usage_history[role_lower][-self._history_length:]
            display.history = list(self._usage_history[role_lower])

            self._last_update = datetime.now(UTC)
            return display

    def set_role_budget(self, role: str, budget: int) -> None:
        """Set or update budget for a role."""
        with self._lock:
            role_lower = role.lower()
            self._budgets[role_lower] = budget
            if role_lower in self._role_data:
                display = self._role_data[role_lower]
                display.budget = budget
                display.remaining = max(0, budget - display.used)
                display.percentage = display.used / budget if budget > 0 else 0
                display.status = self._calculate_status(display.percentage)
            self._last_update = datetime.now(UTC)

    def get_role_status(self, role: str) -> RoleBudgetDisplay | None:
        """Get current status for a role."""
        with self._lock:
            return self._role_data.get(role.lower())

    def get_all_status(self) -> dict[str, RoleBudgetDisplay]:
        """Get status for all roles."""
        with self._lock:
            return dict(self._role_data)

    def reset_role(self, role: str) -> None:
        """Reset usage for a role."""
        with self._lock:
            role_lower = role.lower()
            if role_lower in self._role_data:
                display = self._role_data[role_lower]
                display.used = 0
                display.remaining = display.budget
                display.percentage = 0.0
                display.status = StatusLevel.NORMAL
                self._usage_history[role_lower] = []
                display.history = []
            self._last_update = datetime.now(UTC)

    def reset_all(self) -> None:
        """Reset all role usages."""
        with self._lock:
            for role in self._role_data:
                self._role_data[role].used = 0
                self._role_data[role].remaining = self._role_data[role].budget
                self._role_data[role].percentage = 0.0
                self._role_data[role].status = StatusLevel.NORMAL
                self._usage_history[role] = []
                self._role_data[role].history = []
            self._last_update = datetime.now(UTC)

    def render(self) -> str:
        """
        Render the complete dashboard.

        Returns:
            Formatted dashboard string
        """
        with self._lock:
            lines = []
            timestamp = self._last_update.strftime("%Y-%m-%d %H:%M:%S")

            # Header
            header = f" {self._color(AnsiColors.BOLD + AnsiColors.CYAN, 'TOKEN BUDGET DASHBOARD')} "
            subtitle = f"{self._color(AnsiColors.MUTED, 'Last update:')} {timestamp}"

            lines.append(self._color(AnsiColors.BG_BLUE, " ")[:self._output_width])
            lines.append(f"{self._color(AnsiColors.BG_BLUE, '')}{header:<{self._output_width - 20}}{subtitle}{AnsiColors.RESET}")
            lines.append(self._color(AnsiColors.BG_BLUE, " ")[:self._output_width])
            lines.append("")

            # Legend
            legend_items = [
                (StatusLevel.NORMAL, "OK"),
                (StatusLevel.WARNING, "Warning"),
                (StatusLevel.CRITICAL, "Critical"),
                (StatusLevel.EXHAUSTED, "Exhausted"),
            ]
            legend = "  ".join(
                f"{self._get_status_icon(s)} {self._get_status_color(s)}{label}{AnsiColors.RESET}"
                for s, label in legend_items
            )
            lines.append(f"  {legend}")
            lines.append("")

            # Column headers
            bar_space = self._output_width - self.ROLE_WIDTH - self.BUDGET_WIDTH - self.PERCENT_WIDTH - 10
            headers = (
                f"  {self._color(AnsiColors.BOLD, 'ROLE'):<{self.ROLE_WIDTH}}"
                f"{self._color(AnsiColors.BOLD, 'USAGE'):<{self.BUDGET_WIDTH}}"
                f"{self._color(AnsiColors.BOLD, 'PERCENT'):^{self.PERCENT_WIDTH}}"
                f"{self._color(AnsiColors.BOLD, 'PROGRESS'):^{bar_space}}"
            )
            lines.append(headers)
            lines.append(self._color(AnsiColors.MUTED, "  " + "-" * (self._output_width - 4)))

            # Role rows
            for role, display in sorted(self._role_data.items()):
                status_icon = self._get_status_icon(display.status)
                status_color = self._get_status_color(display.status)

                # Usage string
                usage_str = f"{self._format_number(display.used)}/{self._format_number(display.budget)}"
                usage_colored = f"{self._color(status_color, usage_str):<{self.BUDGET_WIDTH}}"

                # Percentage
                pct_str = f"{display.percentage:.1%}"
                pct_colored = f"{self._color(status_color, pct_str):^{self.PERCENT_WIDTH}}"

                # Progress bar
                bar = self._render_progress_bar(
                    min(display.percentage, 1.0),
                    width=bar_space - 2,
                    status=display.status,
                )

                # Role name with status
                role_display = f"{status_icon} {display.role_display}"
                role_colored = f"{self._color(AnsiColors.BOLD, role_display):<{self.ROLE_WIDTH}}"

                # Remaining
                remaining_str = f"({self._format_number(display.remaining)} left)"
                remaining_colored = self._color(AnsiColors.MUTED, remaining_str)

                line = f"  {role_colored}{usage_colored}{pct_colored}{bar}"
                if display.remaining < display.budget * 0.2:
                    line += f" {remaining_colored}"
                lines.append(line)

                # History sparkline
                if self._show_history and display.history:
                    sparkline = self._render_sparkline(display.history, width=bar_space - 4)
                    lines.append(f"  {' ':<{self.ROLE_WIDTH + self.BUDGET_WIDTH + self.PERCENT_WIDTH + 3}}{sparkline}")

            lines.append("")

            # Summary statistics
            total_budget = sum(d.budget for d in self._role_data.values())
            total_used = sum(d.used for d in self._role_data.values())
            overall_pct = total_used / total_budget if total_budget > 0 else 0

            # Count by status
            status_counts = {s: 0 for s in StatusLevel}
            for display in self._role_data.values():
                status_counts[display.status] += 1

            lines.append(self._color(AnsiColors.MUTED, "  " + "─" * (self._output_width - 4)))
            lines.append(f"  {self._color(AnsiColors.BOLD, 'TOTAL')}: {self._format_number(total_used)}/{self._format_number(total_budget)} ({overall_pct:.1%})")

            # Status summary
            status_parts = []
            for status, count in status_counts.items():
                if count > 0:
                    icon = self._get_status_icon(status)
                    color = self._get_status_color(status)
                    status_parts.append(f"{icon} {self._color(color, str(count))}")

            if status_parts:
                lines.append(f"  {self._color(AnsiColors.BOLD, 'STATUS')}: {'  '.join(status_parts)}")

            # Footer
            lines.append("")
            lines.append(self._color(AnsiColors.MUTED, f"  Refresh: {self._refresh_interval}s | Thresholds: {self._warning_threshold:.0%} warning, {self._critical_threshold:.0%} critical"))

            return "\n".join(lines)

    def render_compact(self) -> str:
        """Render a compact single-line status for each role."""
        with self._lock:
            parts = []
            for role, display in sorted(self._role_data.items()):
                icon = self._get_status_icon(display.status)
                pct = f"{display.percentage:.0%}"
                parts.append(f"{icon} {role}:{pct}")

            return " | ".join(parts)

    def print(self) -> None:
        """Print dashboard to stdout."""
        output = self.render()
        if self._use_colors and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            # Use ANSI escape to clear and reposition
            sys.stdout.write(AnsiColors.clear_screen())
            sys.stdout.write(output)
            sys.stdout.flush()
        else:
            # Strip ANSI codes for non-TTY
            import re
            clean = re.sub(r'\x1b\[[0-9;]*m', '', output)
            sys.stdout.write(clean)
            sys.stdout.flush()

    def _update_loop(self) -> None:
        """Background update loop."""
        while self._running:
            self.print()
            time.sleep(self._refresh_interval)

    def start(self) -> None:
        """Start background dashboard updates."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self._update_thread.start()

    def stop(self) -> None:
        """Stop background dashboard updates."""
        with self._lock:
            self._running = False
            if self._update_thread:
                self._update_thread.join(timeout=2.0)
                self._update_thread = None

    def export_csv(self, filepath: str) -> None:
        """Export current state to CSV."""
        import csv
        with self._lock:
            displays = list(self._role_data.values())
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Role', 'Budget', 'Used', 'Remaining', 'Percentage', 'Status'])
            for display in displays:
                writer.writerow([
                    display.role,
                    display.budget,
                    display.used,
                    display.remaining,
                    f"{display.percentage:.2%}",
                    display.status.value,
                ])


class LiveBudgetMonitor:
    """
    Live monitor that integrates with TokenBudgetCounter.
    Provides real-time dashboard updates as tokens are consumed.
    """

    def __init__(
        self,
        budget_counter: Any = None,
        refresh_interval: float = 0.5,
        output_width: int = 80,
    ):
        """
        Initialize live monitor.

        Args:
            budget_counter: TokenBudgetCounter instance to monitor
            refresh_interval: Seconds between display updates
            output_width: Terminal width
        """
        self._counter = budget_counter
        self._dashboard = BudgetDashboard(
            budgets=None,  # Will be populated from counter
            refresh_interval=refresh_interval,
            output_width=output_width,
        )
        self._running = False
        self._monitor_thread: threading.Thread | None = None
        self._lock = threading.RLock()

        # Sync initial state
        if budget_counter:
            self._sync_from_counter()

    def _sync_from_counter(self) -> None:
        """Sync dashboard state from counter."""
        if not self._counter:
            return

        with self._lock:
            all_status = self._counter.get_all_status()
            for role, status in all_status.items():
                self._dashboard.set_role_budget(role, status.budget)
                self._dashboard.set_role_usage(role, status.used)

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                if self._counter:
                    self._sync_from_counter()
                self._dashboard.print()
                time.sleep(self._dashboard._refresh_interval)
            except Exception:
                pass

    def update(self, role: str, tokens: int, token_type: str = "prompt") -> None:
        """Update token usage and refresh display."""
        with self._lock:
            if self._counter and hasattr(self._counter, "add_tokens"):
                self._counter.add_tokens(role, tokens, token_type)
                self._sync_from_counter()
            else:
                self._dashboard.update_role(role, tokens, token_type)

    def start(self) -> None:
        """Start live monitoring."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

    def stop(self) -> None:
        """Stop live monitoring."""
        with self._lock:
            self._running = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=2.0)
                self._monitor_thread = None

    def get_dashboard(self) -> BudgetDashboard:
        """Get the underlying dashboard."""
        with self._lock:
            return self._dashboard


def demo_dashboard() -> None:
    """Demonstrate the budget dashboard."""
    print("Starting Budget Dashboard Demo...")
    print("Press Ctrl+C to exit\n")

    dashboard = BudgetDashboard(
        warning_threshold=0.80,
        critical_threshold=0.95,
        refresh_interval=0.5,
        show_history=True,
    )

    # Simulate some initial usage
    dashboard.update_role("pm", 5000)
    dashboard.update_role("dev", 3000)
    dashboard.update_role("qa", 8000)
    dashboard.update_role("tl", 2000)

    dashboard.print()

    # Simulate usage over time
    import random
    for i in range(20):
        time.sleep(0.3)

        # Add random usage
        role = random.choice(["pm", "dev", "qa", "tl"])
        tokens = random.randint(100, 500)
        dashboard.update_role(role, tokens)

        # Show compact status
        print("\n\033[2A")  # Move up 2 lines
        print(dashboard.render_compact())

    print("\n\nDashboard Demo Complete!")


if __name__ == "__main__":
    try:
        demo_dashboard()
    except KeyboardInterrupt:
        print("\n\nDashboard stopped.")
