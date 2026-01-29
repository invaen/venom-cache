"""Output formatting module with color support and TTY detection.

Provides professional terminal output with ANSI colors, respecting the NO_COLOR
standard and providing JSON/quiet mode infrastructure.
"""

import os
import sys
from enum import Enum
from typing import Dict


class OutputMode(Enum):
    """Output format modes."""

    NORMAL = "normal"
    JSON = "json"
    QUIET = "quiet"


class Severity(Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ANSI color codes
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BRIGHT_RED = "\033[1;31m"
RESET = "\033[0m"

# Severity to color code mapping
SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.INFO: CYAN,
    Severity.LOW: GREEN,
    Severity.MEDIUM: YELLOW,
    Severity.HIGH: RED,
    Severity.CRITICAL: BRIGHT_RED,
}


class Output:
    """Terminal output handler with color support and TTY detection.

    Respects NO_COLOR and FORCE_COLOR environment variables per the NO_COLOR
    standard (https://no-color.org/).

    Args:
        mode: Output format mode (NORMAL, JSON, QUIET).
        verbosity: Verbosity level (0 = normal, 1 = verbose, 2+ = debug).
        force_color: Override TTY detection and force color output.
    """

    def __init__(
        self,
        mode: OutputMode,
        verbosity: int,
        force_color: bool = False,
    ) -> None:
        self.mode = mode
        self.verbosity = verbosity
        self._color_enabled = self._detect_color_support(force_color)
        self._enable_windows_ansi()

    def _detect_color_support(self, force_color: bool) -> bool:
        """Detect whether color output should be enabled.

        Priority order:
        1. NO_COLOR env var (if set and non-empty, disables color)
        2. FORCE_COLOR env var or force_color param (enables color)
        3. TTY detection (enable if stdout is a terminal)

        Args:
            force_color: Force color output regardless of TTY.

        Returns:
            True if colors should be used, False otherwise.
        """
        # NO_COLOR takes precedence - any non-empty value disables color
        no_color = os.environ.get("NO_COLOR", "")
        if no_color:
            return False

        # FORCE_COLOR or force_color param enables color
        force_color_env = os.environ.get("FORCE_COLOR", "")
        if force_color_env or force_color:
            return True

        # Fall back to TTY detection
        return sys.stdout.isatty()

    def _enable_windows_ansi(self) -> bool:
        """Enable ANSI escape sequences on Windows.

        Windows 10+ supports ANSI but needs to enable virtual terminal
        processing mode via SetConsoleMode with flag 0x0004.

        Returns:
            True if successfully enabled or not needed, False on failure.
        """
        if sys.platform != "win32":
            return True

        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            # Get stdout handle (-11)
            handle = kernel32.GetStdHandle(-11)
            # Get current console mode
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            # Enable virtual terminal processing (0x0004)
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False

    @property
    def color_enabled(self) -> bool:
        """Return whether color output is enabled."""
        return self._color_enabled

    def color(self, text: str, code: str) -> str:
        """Apply ANSI color code to text if colors are enabled.

        Args:
            text: The text to colorize.
            code: The ANSI code (e.g., "31" for red, "1;31" for bright red).

        Returns:
            Colorized text if colors enabled, plain text otherwise.
        """
        if not self._color_enabled:
            return text
        return f"\033[{code}m{text}{RESET}"

    def format_severity(self, severity: Severity) -> str:
        """Format a severity level as a colored bracketed label.

        Args:
            severity: The severity level to format.

        Returns:
            Formatted string like "[HIGH]" or "[CRITICAL]" with color if enabled.
        """
        label = f"[{severity.value.upper()}]"
        if not self._color_enabled:
            return label

        color_code = SEVERITY_COLORS.get(severity, "")
        if not color_code:
            return label

        return f"{color_code}{label}{RESET}"
