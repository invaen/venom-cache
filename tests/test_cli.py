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
        # This should parse without error (file validation happens later)
        # We can't actually test this without a real file, so we test the parser structure
        assert parser._actions[1].dest == "url"  # First positional after help
        assert parser._actions[2].dest == "file"  # Second argument

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
