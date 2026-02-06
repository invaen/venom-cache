"""Tests for CLI argument parsing and URL extraction."""

import argparse
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from venom_cache.cli import (
    build_parser,
    build_request_headers,
    get_target_urls,
    parse_cookie,
    parse_header,
    validate_wordlist_path,
)


class TestBuildParser:
    """Tests for argument parser construction."""

    def test_url_positional_still_works(self):
        """Positional URL argument should still work for backward compatibility."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_url_optional_when_file_given(self):
        """URL should be optional when --file is provided."""
        parser = build_parser()
        # Parse with just -f flag (using a mock file)
        with patch("builtins.open", return_value=StringIO("https://test.com\n")):
            # Note: argparse.FileType opens the file immediately
            # We need to provide a real file path that will be mocked
            args = parser.parse_args(["-f", "/dev/stdin"])
        assert args.url is None
        assert args.file is not None

    def test_url_is_none_when_not_provided(self):
        """URL should be None when no positional argument provided."""
        parser = build_parser()
        args = parser.parse_args([])
        assert args.url is None

    def test_file_argument_with_short_flag(self):
        """The -f short flag should work."""
        parser = build_parser()
        # Just verify the parser accepts -f
        with pytest.raises(SystemExit):
            # This will fail because file doesn't exist, but confirms -f is recognized
            parser.parse_args(["-f", "/nonexistent/file.txt"])

    def test_file_argument_with_long_flag(self):
        """The --file long flag should work."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--file", "/nonexistent/file.txt"])

    def test_url_and_file_can_coexist(self):
        """Both positional URL and --file can be provided together."""
        parser = build_parser()
        # Verify parser has both url and file actions by dest name
        action_dests = [a.dest for a in parser._actions]
        assert "url" in action_dests
        assert "file" in action_dests

    def test_help_shows_file_option(self):
        """Help text should document the file input option."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "-f FILE" in help_text or "--file FILE" in help_text
        assert "File containing URLs" in help_text

    def test_help_shows_stdin_example(self):
        """Help text should show stdin example with -f -."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "-f -" in help_text


class TestGetTargetUrls:
    """Tests for URL extraction from command line arguments."""

    def test_urls_from_positional(self):
        """Single URL should be returned when provided as positional."""
        args = argparse.Namespace(url="https://example.com", file=None)
        urls = get_target_urls(args)
        assert urls == ["https://example.com"]

    def test_urls_from_file(self):
        """Multiple URLs should be extracted from file."""
        mock_file = StringIO("https://site1.com\nhttps://site2.com\nhttps://site3.com\n")
        mock_file.close = MagicMock()  # Prevent actual close
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com", "https://site2.com", "https://site3.com"]
        mock_file.close.assert_called_once()

    def test_urls_from_both_positional_and_file(self):
        """URLs from both positional and file should be combined."""
        mock_file = StringIO("https://site2.com\nhttps://site3.com\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url="https://site1.com", file=mock_file)
        urls = get_target_urls(args)
        # Positional URL comes first
        assert urls == ["https://site1.com", "https://site2.com", "https://site3.com"]

    def test_empty_lines_skipped(self):
        """Empty lines in URL file should be skipped."""
        mock_file = StringIO("https://site1.com\n\n\nhttps://site2.com\n\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com", "https://site2.com"]

    def test_whitespace_only_lines_skipped(self):
        """Lines with only whitespace should be skipped."""
        mock_file = StringIO("https://site1.com\n   \n\t\nhttps://site2.com\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com", "https://site2.com"]

    def test_comment_lines_skipped(self):
        """Lines starting with # should be skipped as comments."""
        mock_file = StringIO("# This is a comment\nhttps://site1.com\n# Another comment\nhttps://site2.com\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com", "https://site2.com"]

    def test_comment_with_leading_whitespace(self):
        """Comments should only be detected at start of line (after strip)."""
        mock_file = StringIO("  # Comment with leading spaces\nhttps://site1.com\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com"]

    def test_urls_are_stripped(self):
        """URLs should have surrounding whitespace removed."""
        mock_file = StringIO("  https://site1.com  \n\thttps://site2.com\t\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        urls = get_target_urls(args)
        assert urls == ["https://site1.com", "https://site2.com"]

    def test_error_when_no_input(self):
        """ValueError should be raised when neither URL nor file provided."""
        args = argparse.Namespace(url=None, file=None)
        with pytest.raises(ValueError) as exc_info:
            get_target_urls(args)
        assert "Provide a URL or use -f/--file" in str(exc_info.value)

    def test_error_when_file_is_empty(self):
        """ValueError should be raised when file contains no valid URLs."""
        mock_file = StringIO("# Only comments\n\n# More comments\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        with pytest.raises(ValueError) as exc_info:
            get_target_urls(args)
        assert "Provide a URL or use -f/--file" in str(exc_info.value)

    def test_file_is_closed_after_reading(self):
        """File should be closed after reading URLs."""
        mock_file = StringIO("https://site1.com\n")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        get_target_urls(args)
        mock_file.close.assert_called_once()

    def test_file_closed_even_on_empty_file(self):
        """File should be closed even if it results in no URLs."""
        mock_file = StringIO("")
        mock_file.close = MagicMock()
        args = argparse.Namespace(url=None, file=mock_file)
        try:
            get_target_urls(args)
        except ValueError:
            pass
        mock_file.close.assert_called_once()


class TestStdinSupport:
    """Tests for stdin support with -f -."""

    def test_stdin_pattern_recognized(self):
        """The -f - pattern should be recognized by argparse."""
        parser = build_parser()
        # When using - for stdin, argparse.FileType should recognize it
        # We can verify the parser is configured correctly
        file_action = None
        for action in parser._actions:
            if action.dest == "file":
                file_action = action
                break
        assert file_action is not None
        # FileType instances don't compare equal, so check the type and mode
        assert isinstance(file_action.type, type(argparse.FileType("r")))
        assert file_action.type._mode == "r"


class TestParseHeader:
    """Tests for parse_header() type converter."""

    def test_parse_header_valid(self):
        """Valid 'Name: Value' should return tuple."""
        result = parse_header("X-Custom: test-value")
        assert result == ("X-Custom", "test-value")

    def test_parse_header_with_spaces(self):
        """Leading/trailing whitespace should be stripped."""
        result = parse_header(" Name : Value ")
        assert result == ("Name", "Value")

    def test_parse_header_colon_in_value(self):
        """Colons in value should be preserved."""
        result = parse_header("Host: example.com:8080")
        assert result == ("Host", "example.com:8080")

    def test_parse_header_multiple_colons(self):
        """Multiple colons: split on first only."""
        result = parse_header("Name: a:b:c")
        assert result == ("Name", "a:b:c")

    def test_parse_header_no_colon_raises(self):
        """Missing colon should raise ArgumentTypeError."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            parse_header("InvalidHeader")
        assert "Invalid header format" in str(exc_info.value)
        assert "expected 'Name: Value'" in str(exc_info.value)

    def test_parse_header_empty_value(self):
        """Empty value after colon is valid."""
        result = parse_header("X-Empty:")
        assert result == ("X-Empty", "")


class TestParseCookie:
    """Tests for parse_cookie() type converter."""

    def test_parse_cookie_valid(self):
        """Valid 'name=value' should return tuple."""
        result = parse_cookie("session=abc123")
        assert result == ("session", "abc123")

    def test_parse_cookie_equals_in_value(self):
        """Equals signs in value should be preserved."""
        result = parse_cookie("token=a=b=c")
        assert result == ("token", "a=b=c")

    def test_parse_cookie_with_spaces(self):
        """Leading/trailing whitespace should be stripped."""
        result = parse_cookie(" name = value ")
        assert result == ("name", "value")

    def test_parse_cookie_no_equals_raises(self):
        """Missing equals should raise ArgumentTypeError."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            parse_cookie("invalid")
        assert "Invalid cookie format" in str(exc_info.value)
        assert "expected 'name=value'" in str(exc_info.value)

    def test_parse_cookie_empty_value(self):
        """Empty value after equals is valid."""
        result = parse_cookie("empty=")
        assert result == ("empty", "")


class TestBuildRequestHeaders:
    """Tests for build_request_headers() helper."""

    def test_build_headers_from_list(self):
        """List of tuples should convert to dict."""
        headers = build_request_headers(
            [("X-Custom", "value1"), ("X-Another", "value2")],
            [],
        )
        assert headers == {"X-Custom": "value1", "X-Another": "value2"}

    def test_build_headers_with_cookies(self):
        """Cookies should be combined into Cookie header."""
        headers = build_request_headers(
            [],
            [("session", "abc123"), ("user", "john")],
        )
        assert headers == {"Cookie": "session=abc123; user=john"}

    def test_build_headers_empty(self):
        """Empty inputs should return empty dict."""
        headers = build_request_headers([], [])
        assert headers == {}

    def test_build_headers_combined(self):
        """Both headers and cookies should be combined."""
        headers = build_request_headers(
            [("X-API-Key", "secret")],
            [("session", "xyz")],
        )
        assert headers == {"X-API-Key": "secret", "Cookie": "session=xyz"}


class TestHeaderAndCookieCLI:
    """Tests for CLI integration of header and cookie flags."""

    def test_header_flag_parses(self):
        """The -H flag should parse headers into list of tuples."""
        parser = build_parser()
        args = parser.parse_args(["-H", "X-Test: value", "https://example.com"])
        assert args.headers == [("X-Test", "value")]

    def test_cookie_flag_parses(self):
        """The -c flag should parse cookies into list of tuples."""
        parser = build_parser()
        args = parser.parse_args(["-c", "session=abc", "https://example.com"])
        assert args.cookies == [("session", "abc")]

    def test_multiple_headers(self):
        """Multiple -H flags should collect all headers."""
        parser = build_parser()
        args = parser.parse_args([
            "-H", "X-First: 1",
            "-H", "X-Second: 2",
            "https://example.com",
        ])
        assert args.headers == [("X-First", "1"), ("X-Second", "2")]

    def test_multiple_cookies(self):
        """Multiple -c flags should collect all cookies."""
        parser = build_parser()
        args = parser.parse_args([
            "-c", "a=1",
            "-c", "b=2",
            "https://example.com",
        ])
        assert args.cookies == [("a", "1"), ("b", "2")]

    def test_default_empty_headers(self):
        """Default headers should be empty list."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.headers == []

    def test_default_empty_cookies(self):
        """Default cookies should be empty list."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.cookies == []


class TestValidateWordlistPath:
    """Tests for validate_wordlist_path() type converter."""

    def test_wordlist_validates_existing_file(self, tmp_path):
        """Valid file path should be accepted."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("X-Test\n")
        result = validate_wordlist_path(str(wordlist_file))
        assert result == str(wordlist_file)

    def test_wordlist_nonexistent_raises(self):
        """Missing file should raise ArgumentTypeError."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            validate_wordlist_path("/nonexistent/wordlist.txt")
        assert "Wordlist not found" in str(exc_info.value)

    def test_wordlist_directory_raises(self, tmp_path):
        """Directory path should raise ArgumentTypeError."""
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            validate_wordlist_path(str(tmp_path))
        assert "Not a file" in str(exc_info.value)


class TestWordlistCLI:
    """Tests for CLI wordlist argument integration."""

    def test_wordlist_argument_in_help(self):
        """The -w/--wordlist flag should appear in help."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "-w FILE" in help_text or "--wordlist FILE" in help_text
        assert "Custom header wordlist" in help_text

    def test_wordlist_argument_accepts_valid(self, tmp_path):
        """Valid wordlist file should be accepted."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("X-Test\n")
        parser = build_parser()
        args = parser.parse_args(["-w", str(wordlist_file), "https://example.com"])
        assert args.wordlist == str(wordlist_file)

    def test_wordlist_argument_validates(self):
        """Invalid wordlist path should cause parser error."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-w", "/nonexistent.txt", "https://example.com"])

    def test_wordlist_default_is_none(self):
        """Default wordlist should be None (use built-in)."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.wordlist is None


class TestQuietModeCLI:
    """Tests for -q/--quiet flag."""

    def test_quiet_short_flag(self):
        """The -q short flag should set quiet=True."""
        parser = build_parser()
        args = parser.parse_args(["-q", "https://example.com"])
        assert args.quiet is True

    def test_quiet_long_flag(self):
        """The --quiet long flag should set quiet=True."""
        parser = build_parser()
        args = parser.parse_args(["--quiet", "https://example.com"])
        assert args.quiet is True

    def test_quiet_default_false(self):
        """Quiet should default to False."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.quiet is False

    def test_quiet_in_help(self):
        """Help text should document the quiet flag."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "-q" in help_text
        assert "--quiet" in help_text
        assert "vulnerability findings" in help_text.lower() or "quiet" in help_text.lower()


class TestJsonModeCLI:
    """Tests for --json flag."""

    def test_json_flag(self):
        """The --json flag should set json=True."""
        parser = build_parser()
        args = parser.parse_args(["--json", "https://example.com"])
        assert args.json is True

    def test_json_short_flag(self):
        """The -j short flag should set json=True."""
        parser = build_parser()
        args = parser.parse_args(["-j", "https://example.com"])
        assert args.json is True

    def test_json_default_false(self):
        """JSON should default to False."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.json is False

    def test_json_and_quiet_can_coexist(self):
        """Both --json and --quiet can be specified (JSON takes precedence)."""
        parser = build_parser()
        args = parser.parse_args(["--json", "--quiet", "https://example.com"])
        assert args.json is True
        assert args.quiet is True

    def test_json_in_help(self):
        """Help text should document the json flag."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "--json" in help_text
        assert "-j" in help_text


class TestJsonOutputIntegration:
    """Integration tests for JSON output mode."""

    def test_json_mode_output_structure(self):
        """JSON mode should produce valid JSON with expected structure."""
        import json
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        # Create output handler in JSON mode
        out = Output(OutputMode.JSON, 0)
        out.set_metadata("https://test.example.com")

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        out.finalize()

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Parse and verify structure
        data = json.loads(output)
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data

        # Verify metadata fields
        assert data["metadata"]["tool"] == "venom-cache"
        assert data["metadata"]["target_url"] == "https://test.example.com"
        assert "scan_started" in data["metadata"]
        assert "scan_completed" in data["metadata"]
        assert "scan_duration_seconds" in data["metadata"]

        # Verify summary structure
        assert "total_findings" in data["summary"]
        assert "findings_by_type" in data["summary"]
        assert "findings_by_severity" in data["summary"]

    def test_json_mode_suppresses_text(self):
        """JSON mode should not output any text, only final JSON."""
        import json
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        out = Output(OutputMode.JSON, 0)
        out.set_metadata("https://test.example.com")

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        # These should not produce any output in JSON mode
        out.info("This is info")
        out.status("Status update")
        out.success("Success message")

        # Only finalize should produce output
        out.finalize()

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Should be valid JSON, not mixed text
        data = json.loads(output)  # Would fail if there's mixed text
        assert isinstance(data, dict)

    def test_json_mode_no_ansi_codes(self):
        """JSON output should not contain ANSI escape codes."""
        import json
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        # Force color enabled but use JSON mode
        out = Output(OutputMode.JSON, 0, force_color=True)
        out.set_metadata("https://test.example.com")

        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        out.finalize()

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Check for absence of ANSI codes
        assert "\033[" not in output
        assert "\x1b[" not in output

    def test_json_mode_verbose_to_stderr(self):
        """Verbose/debug output should go to stderr, not pollute JSON stdout."""
        import json
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        out = Output(OutputMode.JSON, 2)  # Verbosity level 2
        out.set_metadata("https://test.example.com")

        captured_stdout = StringIO()
        captured_stderr = StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr

        out.debug("Debug message", level=1)
        out.debug("More debug", level=2)
        out.error("Error message")  # Errors always go to stderr
        out.finalize()

        sys.stdout = old_stdout
        sys.stderr = old_stderr

        stdout_output = captured_stdout.getvalue()
        stderr_output = captured_stderr.getvalue()

        # Stdout should be valid JSON only
        data = json.loads(stdout_output)
        assert isinstance(data, dict)

        # Debug and error messages should be in stderr
        assert "Debug message" in stderr_output
        assert "More debug" in stderr_output
        assert "Error message" in stderr_output

    def test_json_mode_with_findings(self):
        """JSON mode should include collected findings."""
        import json
        from io import StringIO
        from dataclasses import dataclass
        from venom_cache.output import Output, OutputMode

        @dataclass
        class MockFinding:
            header_name: str
            canary: str
            reflected_in_body: bool
            reflected_in_headers: list
            is_significant: bool

        out = Output(OutputMode.JSON, 0)
        out.set_metadata("https://test.example.com")

        # Add a mock finding
        finding = MockFinding(
            header_name="X-Forwarded-Host",
            canary="venom-abc123",
            reflected_in_body=True,
            reflected_in_headers=[],
            is_significant=True,
        )
        out.add_finding(finding, "header_poisoning")

        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        out.finalize()

        sys.stdout = old_stdout
        output = captured.getvalue()

        data = json.loads(output)
        assert data["summary"]["total_findings"] == 1
        assert data["summary"]["findings_by_type"]["header_poisoning"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["header_name"] == "X-Forwarded-Host"
        assert data["findings"][0]["finding_type"] == "header_poisoning"


class TestFindingOutputBehavior:
    """Tests for finding display behavior with severity labels."""

    def test_quiet_mode_shows_findings(self):
        """Quiet mode should show vulnerability findings via out.finding()."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode, Severity

        out = Output(OutputMode.QUIET, 0)

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        # Info should be suppressed in quiet mode
        out.info("This should not appear")

        # Findings should still appear
        out.finding(
            finding_type="Header Poisoning",
            name="X-Forwarded-Host",
            severity=Severity.MEDIUM,
            details="Reflected in body",
        )

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Finding should be visible
        assert "[MEDIUM]" in output
        assert "Header Poisoning" in output
        assert "X-Forwarded-Host" in output
        # Info should not appear
        assert "This should not appear" not in output

    def test_findings_have_severity_labels(self):
        """Findings should display with [MEDIUM]/[HIGH] severity labels."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode, Severity

        out = Output(OutputMode.NORMAL, 0)

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        # Test MEDIUM severity
        out.finding(
            finding_type="Header Poisoning",
            name="X-Test",
            severity=Severity.MEDIUM,
            details="Test details",
        )

        # Test HIGH severity
        out.finding(
            finding_type="Web Cache Deception",
            name="/path.css",
            severity=Severity.HIGH,
            details="Vulnerable path",
        )

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Severity labels should appear
        assert "[MEDIUM]" in output
        assert "[HIGH]" in output
        # Old markers should NOT be used
        assert "[!]" not in output
        assert "[*]" not in output
        assert "[+]" not in output

    def test_verbose_mode_shows_debug_output(self):
        """Verbose mode should show debug information on stderr."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        out = Output(OutputMode.NORMAL, 1)  # Verbosity level 1

        # Capture stderr
        captured_stderr = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured_stderr

        out.debug("Debug: Header probe results", level=1)
        out.debug("Debug: Detailed info", level=2)  # Should not appear at level 1

        sys.stderr = old_stderr
        output = captured_stderr.getvalue()

        # Level 1 debug should appear
        assert "Header probe results" in output
        # Level 2 debug should not appear at verbosity 1
        assert "Detailed info" not in output

    def test_verbose_level_2_shows_detailed_debug(self):
        """Verbosity level 2 should show all debug messages."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode

        out = Output(OutputMode.NORMAL, 2)  # Verbosity level 2

        # Capture stderr
        captured_stderr = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured_stderr

        out.debug("Debug: High level", level=1)
        out.debug("Debug: Detailed", level=2)

        sys.stderr = old_stderr
        output = captured_stderr.getvalue()

        # Both levels should appear
        assert "High level" in output
        assert "Detailed" in output

    def test_finding_with_extra_info(self):
        """Finding with extra dict should display additional key-value pairs."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode, Severity

        out = Output(OutputMode.NORMAL, 0)

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        out.finding(
            finding_type="Header Poisoning",
            name="X-Test",
            severity=Severity.MEDIUM,
            details="Reflected in body",
            extra={"canary": "venom-abc123"},
        )

        sys.stdout = old_stdout
        output = captured.getvalue()

        # Extra info should be displayed
        assert "canary" in output
        assert "venom-abc123" in output

    def test_low_severity_findings(self):
        """LOW severity findings should display with [LOW] label."""
        from io import StringIO
        from venom_cache.output import Output, OutputMode, Severity

        out = Output(OutputMode.NORMAL, 0)

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        out.finding(
            finding_type="Header Reflection",
            name="X-Test",
            severity=Severity.LOW,
            details="Reflected but no significant diff",
        )

        sys.stdout = old_stdout
        output = captured.getvalue()

        assert "[LOW]" in output
        assert "Header Reflection" in output


class TestDelayCLI:
    """Tests for --delay flag.

    SAFE-03 (canary values) is already implemented via generate_canary() in
    header_prober.py. This class focuses on SAFE-05 (rate limiting via --delay).
    """

    def test_delay_default(self):
        """Default delay should be 0.0 (no rate limiting)."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.delay == 0.0

    def test_delay_custom(self):
        """Custom delay should be parsed as float."""
        parser = build_parser()
        args = parser.parse_args(["--delay", "0.5", "https://example.com"])
        assert args.delay == 0.5

    def test_delay_integer(self):
        """Integer delay should be accepted and parsed as float."""
        parser = build_parser()
        args = parser.parse_args(["--delay", "2", "https://example.com"])
        assert args.delay == 2.0

    def test_delay_small_value(self):
        """Small delay values should be accepted."""
        parser = build_parser()
        args = parser.parse_args(["--delay", "0.1", "https://example.com"])
        assert args.delay == 0.1

    def test_delay_large_value(self):
        """Large delay values should be accepted."""
        parser = build_parser()
        args = parser.parse_args(["--delay", "10.0", "https://example.com"])
        assert args.delay == 10.0

    def test_delay_invalid_raises(self):
        """Non-numeric delay should cause parser error."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--delay", "not-a-number", "https://example.com"])

    def test_delay_in_help(self):
        """Help text should document the delay flag."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "--delay" in help_text
        assert "SECONDS" in help_text
        assert "Delay between requests" in help_text

    def test_delay_with_other_flags(self):
        """Delay should work alongside other flags."""
        parser = build_parser()
        args = parser.parse_args([
            "--delay", "1.0",
            "--timeout", "30",
            "-v",
            "https://example.com",
        ])
        assert args.delay == 1.0
        assert args.timeout == 30.0
        assert args.verbose == 1


class TestConfirmCLI:
    """Tests for --confirm flag (SAFE-04)."""

    def test_confirm_default(self):
        """Default confirm should be False."""
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.confirm is False

    def test_confirm_enabled(self):
        """--confirm flag should set confirm=True."""
        parser = build_parser()
        args = parser.parse_args(["--confirm", "https://example.com"])
        assert args.confirm is True

    def test_confirm_with_delay(self):
        """--confirm can combine with --delay."""
        parser = build_parser()
        args = parser.parse_args(["--confirm", "--delay", "1.0", "https://example.com"])
        assert args.confirm is True
        assert args.delay == 1.0

    def test_confirm_with_all(self):
        """--confirm can combine with --all."""
        parser = build_parser()
        args = parser.parse_args(["--confirm", "--all", "https://example.com"])
        assert args.confirm is True

    def test_confirm_with_verbose(self):
        """--confirm can combine with verbose flags."""
        parser = build_parser()
        args = parser.parse_args(["--confirm", "-vv", "https://example.com"])
        assert args.confirm is True
        assert args.verbose == 2

    def test_confirm_in_help(self):
        """Help text should document the --confirm flag with warning."""
        parser = build_parser()
        help_text = parser.format_help()
        assert "--confirm" in help_text
        assert "WARNING" in help_text
        assert "shared cache" in help_text.lower()

    def test_confirm_with_multiple_flags(self):
        """--confirm should work with multiple other flags."""
        parser = build_parser()
        args = parser.parse_args([
            "--confirm",
            "--delay", "0.5",
            "--timeout", "15",
            "--insecure",
            "-v",
            "https://example.com",
        ])
        assert args.confirm is True
        assert args.delay == 0.5
        assert args.timeout == 15.0
        assert args.insecure is True
        assert args.verbose == 1
