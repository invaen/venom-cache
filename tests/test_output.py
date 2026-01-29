"""Tests for output formatting module."""

import os
from unittest.mock import patch

import pytest

from venom_cache.output import (
    BRIGHT_RED,
    CYAN,
    GREEN,
    RED,
    RESET,
    SEVERITY_COLORS,
    YELLOW,
    Output,
    OutputMode,
    Severity,
)


class TestOutputModeEnum:
    """Tests for OutputMode enum values."""

    def test_normal_value(self):
        """NORMAL mode should have 'normal' value."""
        assert OutputMode.NORMAL.value == "normal"

    def test_json_value(self):
        """JSON mode should have 'json' value."""
        assert OutputMode.JSON.value == "json"

    def test_quiet_value(self):
        """QUIET mode should have 'quiet' value."""
        assert OutputMode.QUIET.value == "quiet"

    def test_all_modes_exist(self):
        """All three output modes should exist."""
        modes = list(OutputMode)
        assert len(modes) == 3
        assert OutputMode.NORMAL in modes
        assert OutputMode.JSON in modes
        assert OutputMode.QUIET in modes


class TestSeverityEnum:
    """Tests for Severity enum values."""

    def test_info_value(self):
        """INFO severity should have 'info' value."""
        assert Severity.INFO.value == "info"

    def test_low_value(self):
        """LOW severity should have 'low' value."""
        assert Severity.LOW.value == "low"

    def test_medium_value(self):
        """MEDIUM severity should have 'medium' value."""
        assert Severity.MEDIUM.value == "medium"

    def test_high_value(self):
        """HIGH severity should have 'high' value."""
        assert Severity.HIGH.value == "high"

    def test_critical_value(self):
        """CRITICAL severity should have 'critical' value."""
        assert Severity.CRITICAL.value == "critical"

    def test_all_severities_exist(self):
        """All five severity levels should exist."""
        severities = list(Severity)
        assert len(severities) == 5

    def test_severity_ordering(self):
        """Severities should be defined in ascending order."""
        severities = list(Severity)
        expected = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        assert severities == expected


class TestSeverityColors:
    """Tests for severity to color mapping."""

    def test_info_color_is_cyan(self):
        """INFO should map to cyan."""
        assert SEVERITY_COLORS[Severity.INFO] == CYAN

    def test_low_color_is_green(self):
        """LOW should map to green."""
        assert SEVERITY_COLORS[Severity.LOW] == GREEN

    def test_medium_color_is_yellow(self):
        """MEDIUM should map to yellow."""
        assert SEVERITY_COLORS[Severity.MEDIUM] == YELLOW

    def test_high_color_is_red(self):
        """HIGH should map to red."""
        assert SEVERITY_COLORS[Severity.HIGH] == RED

    def test_critical_color_is_bright_red(self):
        """CRITICAL should map to bright red."""
        assert SEVERITY_COLORS[Severity.CRITICAL] == BRIGHT_RED

    def test_all_severities_have_colors(self):
        """All severity levels should have a color mapping."""
        for severity in Severity:
            assert severity in SEVERITY_COLORS


class TestOutputConstruction:
    """Tests for Output class initialization."""

    def test_default_construction(self):
        """Output should initialize with mode and verbosity."""
        out = Output(mode=OutputMode.NORMAL, verbosity=0)
        assert out.mode == OutputMode.NORMAL
        assert out.verbosity == 0

    def test_json_mode_construction(self):
        """Output should accept JSON mode."""
        out = Output(mode=OutputMode.JSON, verbosity=0)
        assert out.mode == OutputMode.JSON

    def test_quiet_mode_construction(self):
        """Output should accept QUIET mode."""
        out = Output(mode=OutputMode.QUIET, verbosity=1)
        assert out.mode == OutputMode.QUIET
        assert out.verbosity == 1

    def test_high_verbosity(self):
        """Output should accept high verbosity levels."""
        out = Output(mode=OutputMode.NORMAL, verbosity=3)
        assert out.verbosity == 3


class TestColorDetection:
    """Tests for color support detection with environment variables."""

    def test_no_color_empty_string_allows_color(self):
        """NO_COLOR='' (empty) should not disable colors."""
        with patch.dict(os.environ, {"NO_COLOR": ""}, clear=False):
            with patch("sys.stdout.isatty", return_value=True):
                out = Output(OutputMode.NORMAL, 0)
                assert out.color_enabled is True

    def test_no_color_set_disables_color(self):
        """NO_COLOR='1' should disable colors."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            assert out.color_enabled is False

    def test_no_color_any_value_disables(self):
        """NO_COLOR with any non-empty value should disable colors."""
        with patch.dict(os.environ, {"NO_COLOR": "true"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            assert out.color_enabled is False

    def test_force_color_env_enables_color(self):
        """FORCE_COLOR='1' should enable colors even without TTY."""
        env = {"FORCE_COLOR": "1", "NO_COLOR": ""}
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.stdout.isatty", return_value=False):
                out = Output(OutputMode.NORMAL, 0)
                assert out.color_enabled is True

    def test_force_color_param_enables_color(self):
        """force_color=True param should enable colors."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": ""}, clear=False):
            with patch("sys.stdout.isatty", return_value=False):
                out = Output(OutputMode.NORMAL, 0, force_color=True)
                assert out.color_enabled is True

    def test_no_color_overrides_force_color(self):
        """NO_COLOR should take precedence over FORCE_COLOR."""
        env = {"NO_COLOR": "1", "FORCE_COLOR": "1"}
        with patch.dict(os.environ, env, clear=False):
            out = Output(OutputMode.NORMAL, 0, force_color=True)
            assert out.color_enabled is False

    def test_tty_detection_enables_color(self):
        """TTY detection should enable colors when env vars not set."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": ""}, clear=False):
            with patch("sys.stdout.isatty", return_value=True):
                out = Output(OutputMode.NORMAL, 0)
                assert out.color_enabled is True

    def test_no_tty_disables_color(self):
        """Non-TTY should disable colors when env vars not set."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": ""}, clear=False):
            with patch("sys.stdout.isatty", return_value=False):
                out = Output(OutputMode.NORMAL, 0)
                assert out.color_enabled is False


class TestColorMethod:
    """Tests for the color() method."""

    def test_color_applies_when_enabled(self):
        """color() should apply ANSI code when colors enabled."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.color("test", "31")
            assert result == "\033[31mtest\033[0m"

    def test_color_returns_plain_when_disabled(self):
        """color() should return plain text when colors disabled."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.color("test", "31")
            assert result == "test"

    def test_color_with_bright_code(self):
        """color() should handle bright/bold codes like '1;31'."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.color("warning", "1;31")
            assert result == "\033[1;31mwarning\033[0m"

    def test_color_preserves_empty_string(self):
        """color() should handle empty strings."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.color("", "32")
            assert result == "\033[32m\033[0m"


class TestFormatSeverity:
    """Tests for format_severity() method."""

    def test_format_severity_info(self):
        """format_severity(INFO) should return '[INFO]'."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.format_severity(Severity.INFO)
            assert result == "[INFO]"

    def test_format_severity_critical(self):
        """format_severity(CRITICAL) should return '[CRITICAL]'."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.format_severity(Severity.CRITICAL)
            assert result == "[CRITICAL]"

    def test_format_severity_with_color(self):
        """format_severity() should colorize when colors enabled."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.format_severity(Severity.HIGH)
            assert result == f"{RED}[HIGH]{RESET}"

    def test_format_severity_critical_with_color(self):
        """CRITICAL should use bright red when colors enabled."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            result = out.format_severity(Severity.CRITICAL)
            assert result == f"{BRIGHT_RED}[CRITICAL]{RESET}"

    def test_format_all_severities(self):
        """All severities should format correctly without color."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            assert out.format_severity(Severity.INFO) == "[INFO]"
            assert out.format_severity(Severity.LOW) == "[LOW]"
            assert out.format_severity(Severity.MEDIUM) == "[MEDIUM]"
            assert out.format_severity(Severity.HIGH) == "[HIGH]"
            assert out.format_severity(Severity.CRITICAL) == "[CRITICAL]"


class TestColorEnabledProperty:
    """Tests for the color_enabled property."""

    def test_color_enabled_reflects_detection(self):
        """color_enabled property should return detection result."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            assert out.color_enabled is True

    def test_color_enabled_readonly(self):
        """color_enabled should be read-only."""
        out = Output(OutputMode.NORMAL, 0)
        # Property shouldn't have a setter
        with pytest.raises(AttributeError):
            out.color_enabled = True  # type: ignore[misc]


class TestAnsiConstants:
    """Tests for ANSI color constants."""

    def test_red_code(self):
        """RED should be ANSI code 31."""
        assert RED == "\033[31m"

    def test_green_code(self):
        """GREEN should be ANSI code 32."""
        assert GREEN == "\033[32m"

    def test_yellow_code(self):
        """YELLOW should be ANSI code 33."""
        assert YELLOW == "\033[33m"

    def test_cyan_code(self):
        """CYAN should be ANSI code 36."""
        assert CYAN == "\033[36m"

    def test_bright_red_code(self):
        """BRIGHT_RED should be ANSI code 1;31."""
        assert BRIGHT_RED == "\033[1;31m"

    def test_reset_code(self):
        """RESET should be ANSI code 0."""
        assert RESET == "\033[0m"


class TestFindingMethod:
    """Tests for finding() method."""

    def test_finding_prints_in_normal_mode(self, capsys):
        """finding() should print in NORMAL mode."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            out.finding("Header Poisoning", "X-Forwarded-Host", Severity.MEDIUM, "Reflected in body")
            captured = capsys.readouterr()
            assert "Header Poisoning" in captured.out
            assert "X-Forwarded-Host" in captured.out
            assert "[MEDIUM]" in captured.out
            assert "Reflected in body" in captured.out

    def test_finding_prints_in_quiet_mode(self, capsys):
        """finding() should print in QUIET mode (that's what quiet is for)."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.QUIET, 0)
            out.finding("Header Poisoning", "X-Test", Severity.HIGH, "Reflected in headers")
            captured = capsys.readouterr()
            assert "Header Poisoning" in captured.out
            assert "X-Test" in captured.out
            assert "[HIGH]" in captured.out

    def test_finding_skipped_in_json_mode(self, capsys):
        """finding() should NOT print in JSON mode."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.JSON, 0)
            out.finding("Header Poisoning", "X-Test", Severity.CRITICAL, "Reflected")
            captured = capsys.readouterr()
            assert captured.out == ""

    def test_finding_with_extra_dict(self, capsys):
        """finding() should print extra key-value pairs."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            out.finding(
                "Header Poisoning",
                "X-Host",
                Severity.MEDIUM,
                "Reflected in body",
                extra={"canary": "venom-abc123"},
            )
            captured = capsys.readouterr()
            assert "canary: venom-abc123" in captured.out

    def test_finding_with_color(self, capsys):
        """finding() should colorize severity when colors enabled."""
        with patch.dict(os.environ, {"NO_COLOR": "", "FORCE_COLOR": "1"}, clear=False):
            out = Output(OutputMode.NORMAL, 0)
            out.finding("Test", "test", Severity.HIGH, "details")
            captured = capsys.readouterr()
            assert RED in captured.out
            assert RESET in captured.out


class TestQuietModeBehavior:
    """Tests for quiet mode behavior across methods."""

    def test_info_skipped_in_quiet_mode(self, capsys):
        """info() should be skipped in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.info("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_status_skipped_in_quiet_mode(self, capsys):
        """status() should be skipped in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.status("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_success_skipped_in_quiet_mode(self, capsys):
        """success() should be skipped in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.success("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_summary_skipped_in_quiet_mode(self, capsys):
        """summary() should be skipped in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.summary("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_section_skipped_in_quiet_mode(self, capsys):
        """section() should be skipped in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.section("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_error_prints_in_quiet_mode(self, capsys):
        """error() should always print to stderr, even in QUIET mode."""
        out = Output(OutputMode.QUIET, 0)
        out.error("Error message")
        captured = capsys.readouterr()
        assert "Error message" in captured.err


class TestNormalModeOutput:
    """Tests for normal mode output behavior."""

    def test_info_prints_in_normal_mode(self, capsys):
        """info() should print in NORMAL mode."""
        out = Output(OutputMode.NORMAL, 0)
        out.info("Info message")
        captured = capsys.readouterr()
        assert "Info message" in captured.out

    def test_status_prints_in_normal_mode(self, capsys):
        """status() should print in NORMAL mode."""
        out = Output(OutputMode.NORMAL, 0)
        out.status("Status update")
        captured = capsys.readouterr()
        assert "Status update" in captured.out

    def test_success_prints_in_normal_mode(self, capsys):
        """success() should print in NORMAL mode."""
        out = Output(OutputMode.NORMAL, 0)
        out.success("Success!")
        captured = capsys.readouterr()
        assert "Success!" in captured.out

    def test_summary_prints_in_normal_mode(self, capsys):
        """summary() should print in NORMAL mode."""
        out = Output(OutputMode.NORMAL, 0)
        out.summary("5 headers tested")
        captured = capsys.readouterr()
        assert "5 headers tested" in captured.out

    def test_section_prints_in_normal_mode(self, capsys):
        """section() should print in NORMAL mode."""
        out = Output(OutputMode.NORMAL, 0)
        out.section("Header Scan")
        captured = capsys.readouterr()
        assert "=== Header Scan ===" in captured.out


class TestJsonModeOutput:
    """Tests for JSON mode output suppression."""

    def test_info_skipped_in_json_mode(self, capsys):
        """info() should be skipped in JSON mode."""
        out = Output(OutputMode.JSON, 0)
        out.info("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_status_skipped_in_json_mode(self, capsys):
        """status() should be skipped in JSON mode."""
        out = Output(OutputMode.JSON, 0)
        out.status("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_summary_skipped_in_json_mode(self, capsys):
        """summary() should be skipped in JSON mode."""
        out = Output(OutputMode.JSON, 0)
        out.summary("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_section_skipped_in_json_mode(self, capsys):
        """section() should be skipped in JSON mode."""
        out = Output(OutputMode.JSON, 0)
        out.section("This should not print")
        captured = capsys.readouterr()
        assert captured.out == ""


class TestDebugMethod:
    """Tests for debug() method."""

    def test_debug_skipped_at_verbosity_0(self, capsys):
        """debug() should be skipped when verbosity is 0."""
        out = Output(OutputMode.NORMAL, 0)
        out.debug("Debug message")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_debug_prints_at_verbosity_1(self, capsys):
        """debug() should print at verbosity 1."""
        out = Output(OutputMode.NORMAL, 1)
        out.debug("Debug message")
        captured = capsys.readouterr()
        assert "Debug message" in captured.err

    def test_debug_goes_to_stderr(self, capsys):
        """debug() output should go to stderr."""
        out = Output(OutputMode.NORMAL, 1)
        out.debug("Debug message")
        captured = capsys.readouterr()
        assert "Debug message" in captured.err
        assert captured.out == ""

    def test_debug_respects_level_parameter(self, capsys):
        """debug() should respect the level parameter."""
        out = Output(OutputMode.NORMAL, 1)
        out.debug("Level 2 debug", level=2)
        captured = capsys.readouterr()
        assert captured.err == ""

        out = Output(OutputMode.NORMAL, 2)
        out.debug("Level 2 debug", level=2)
        captured = capsys.readouterr()
        assert "Level 2 debug" in captured.err


class TestErrorMethod:
    """Tests for error() method."""

    def test_error_always_prints_to_stderr(self, capsys):
        """error() should always print to stderr."""
        out = Output(OutputMode.NORMAL, 0)
        out.error("Error message")
        captured = capsys.readouterr()
        assert "Error message" in captured.err
        assert captured.out == ""

    def test_error_prints_in_json_mode(self, capsys):
        """error() should print even in JSON mode."""
        out = Output(OutputMode.JSON, 0)
        out.error("Error message")
        captured = capsys.readouterr()
        assert "Error message" in captured.err
