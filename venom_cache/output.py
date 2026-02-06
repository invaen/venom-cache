"""Output formatting module with color support and TTY detection.

Provides professional terminal output with ANSI colors, respecting the NO_COLOR
standard and providing JSON/quiet mode infrastructure.
"""

import json
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


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
        # Finding collection for JSON output
        self._findings: List[Dict[str, Any]] = []
        self._metadata: Dict[str, Any] = {}
        self._start_time: float = time.time()

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

    def info(self, message: str) -> None:
        """Print informational message.

        Skipped in QUIET and JSON modes.

        Args:
            message: The message to print.
        """
        if self.mode in (OutputMode.QUIET, OutputMode.JSON):
            return
        print(message)

    def status(self, message: str) -> None:
        """Print status update message.

        Skipped in QUIET and JSON modes.

        Args:
            message: The status message to print.
        """
        if self.mode in (OutputMode.QUIET, OutputMode.JSON):
            return
        print(message)

    def success(self, message: str) -> None:
        """Print success message.

        Skipped in QUIET and JSON modes.

        Args:
            message: The success message to print.
        """
        if self.mode in (OutputMode.QUIET, OutputMode.JSON):
            return
        print(message)

    def error(self, message: str) -> None:
        """Print error message to stderr.

        Always printed regardless of mode.

        Args:
            message: The error message to print.
        """
        print(message, file=sys.stderr)

    def debug(self, message: str, level: int = 1) -> None:
        """Print debug message to stderr if verbosity is high enough.

        Args:
            message: The debug message to print.
            level: Minimum verbosity level required (default 1).
        """
        if self.verbosity >= level:
            print(message, file=sys.stderr)

    def section(self, title: str) -> None:
        """Print section header.

        Skipped in QUIET and JSON modes.

        Args:
            title: The section title to print.
        """
        if self.mode in (OutputMode.QUIET, OutputMode.JSON):
            return
        print(f"\n=== {title} ===")

    def summary(self, text: str) -> None:
        """Print summary line.

        Skipped in QUIET and JSON modes.

        Args:
            text: The summary text to print.
        """
        if self.mode in (OutputMode.QUIET, OutputMode.JSON):
            return
        print(text)

    def finding(
        self,
        finding_type: str,
        name: str,
        severity: Severity,
        details: str,
        extra: dict = None,
    ) -> None:
        """Print a vulnerability finding.

        In NORMAL mode: Print formatted finding with colored severity label.
        In QUIET mode: Print finding (quiet shows ONLY findings).
        In JSON mode: Skip (findings collected via add_finding()).

        Args:
            finding_type: Type of finding (e.g., "Header Poisoning").
            name: Name of the vulnerable element (e.g., header name).
            severity: Severity level of the finding.
            details: Description of the finding.
            extra: Optional dict of additional key-value pairs to display.
        """
        if self.mode == OutputMode.JSON:
            return

        severity_label = self.format_severity(severity)
        print(f"{severity_label} {finding_type}: {name}")
        print(f"    {details}")
        if extra:
            for key, value in extra.items():
                print(f"    {key}: {value}")

    def warning(self, message: str) -> None:
        """Print warning message to stderr.

        Skipped in JSON mode (errors still print).

        Args:
            message: The warning message to print.
        """
        if self.mode == OutputMode.JSON:
            return
        colored_msg = self.color(f"WARNING: {message}", "33") if self._color_enabled else f"WARNING: {message}"
        print(colored_msg, file=sys.stderr)

    def set_metadata(
        self,
        url: str,
        tool: str = "venom-cache",
        version: Optional[str] = None,
    ) -> None:
        """Set scan metadata for JSON output.

        Args:
            url: The target URL being scanned.
            tool: Tool name (default: venom-cache).
            version: Tool version (default: from __init__.__version__).
        """
        if version is None:
            from venom_cache import __version__

            version = __version__
        self._metadata = {
            "tool": tool,
            "version": version,
            "target_url": url,
            "scan_started": datetime.fromtimestamp(
                self._start_time, tz=timezone.utc
            ).isoformat(),
        }

    def add_finding(self, finding: Any, finding_type: str) -> None:
        """Add a finding to the collection for JSON output.

        Args:
            finding: A dataclass finding object (HeaderFinding, ParamFinding, etc.)
            finding_type: Type tag (header_poisoning, parameter_poisoning, fat_get, web_cache_deception)
        """
        finding_dict = finding_to_dict(finding)
        finding_dict["finding_type"] = finding_type
        finding_dict["severity"] = _finding_severity(finding_type, finding)
        self._findings.append(finding_dict)

    def finalize(self) -> None:
        """Finalize output and print JSON if in JSON mode.

        In JSON mode, prints the complete JSON output to stdout.
        In other modes, does nothing.
        """
        if self.mode != OutputMode.JSON:
            return

        end_time = time.time()
        duration = end_time - self._start_time

        # Build summary
        summary = {
            "total_findings": len(self._findings),
            "findings_by_type": {},
            "findings_by_severity": {},
        }

        for f in self._findings:
            ftype = f.get("finding_type", "unknown")
            summary["findings_by_type"][ftype] = summary["findings_by_type"].get(ftype, 0) + 1
            sev = f.get("severity", "info")
            summary["findings_by_severity"][sev] = summary["findings_by_severity"].get(sev, 0) + 1

        # Update metadata with scan completion
        self._metadata["scan_completed"] = datetime.fromtimestamp(
            end_time, tz=timezone.utc
        ).isoformat()
        self._metadata["scan_duration_seconds"] = round(duration, 2)

        output = {
            "metadata": self._metadata,
            "summary": summary,
            "findings": self._findings,
        }

        print(json.dumps(output, indent=2))


def finding_to_dict(finding: Any) -> dict:
    """Convert a finding dataclass to a JSON-serializable dict.

    Handles nested dataclasses like ResponseDiff.

    Args:
        finding: A dataclass finding object.

    Returns:
        Dictionary representation of the finding.
    """
    if not is_dataclass(finding):
        return {"raw": str(finding)}

    result = {}
    for key, value in asdict(finding).items():
        # Skip response_diff as it's verbose and contains computed fields
        if key == "response_diff":
            # Include only the significant flag from response_diff
            if is_dataclass(value):
                result["response_significant"] = value.get("significant", False) if isinstance(value, dict) else getattr(value, "significant", False)
            elif isinstance(value, dict):
                result["response_significant"] = value.get("significant", False)
            continue
        result[key] = value
    return result


def _finding_severity(finding_type: str, finding: Any) -> str:
    """Determine severity level for a finding.

    Args:
        finding_type: Type of finding.
        finding: The finding object.

    Returns:
        Severity string: info, low, medium, high, critical.
    """
    # Check if finding is significant
    is_significant = getattr(finding, "is_significant", False)

    if finding_type == "web_cache_deception":
        return "high" if is_significant else "info"
    elif finding_type in ("header_poisoning", "parameter_poisoning", "fat_get"):
        return "medium" if is_significant else "info"
    else:
        return "info"
