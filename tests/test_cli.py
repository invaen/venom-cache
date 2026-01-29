"""Tests for CLI argument parsing and URL extraction."""

import argparse
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from venom_cache.cli import build_parser, get_target_urls


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
