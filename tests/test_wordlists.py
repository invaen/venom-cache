"""Tests for wordlists module."""

import pytest

from venom_cache.wordlists import (
    UNKEYED_HEADERS,
    get_header_wordlist,
    get_header_wordlist_with_custom,
    load_wordlist_from_file,
)


class TestUnkeyedHeaders:
    """Tests for UNKEYED_HEADERS constant."""

    def test_unkeyed_headers_not_empty(self):
        """Wordlist has items."""
        assert len(UNKEYED_HEADERS) > 0

    def test_unkeyed_headers_minimum_count(self):
        """Wordlist has at least 30 headers."""
        assert len(UNKEYED_HEADERS) >= 30

    def test_unkeyed_headers_contains_x_forwarded_host(self):
        """X-Forwarded-Host is included (most common vector)."""
        assert "X-Forwarded-Host" in UNKEYED_HEADERS

    def test_unkeyed_headers_contains_x_original_url(self):
        """X-Original-URL is included (common vector)."""
        assert "X-Original-URL" in UNKEYED_HEADERS

    def test_unkeyed_headers_contains_x_forwarded_proto(self):
        """X-Forwarded-Proto is included (protocol override vector)."""
        assert "X-Forwarded-Proto" in UNKEYED_HEADERS

    def test_all_headers_are_strings(self):
        """Every item in the list is a string."""
        for header in UNKEYED_HEADERS:
            assert isinstance(header, str)

    def test_no_duplicate_headers(self):
        """No duplicate entries in the list."""
        assert len(UNKEYED_HEADERS) == len(set(UNKEYED_HEADERS))

    def test_headers_are_properly_formatted(self):
        """Headers follow HTTP header naming convention."""
        for header in UNKEYED_HEADERS:
            # Headers should start with a letter
            assert header[0].isalpha()
            # Headers should only contain valid characters
            assert all(c.isalnum() or c == "-" for c in header)


class TestGetHeaderWordlist:
    """Tests for get_header_wordlist function."""

    def test_get_header_wordlist_returns_list(self):
        """Function returns a list."""
        result = get_header_wordlist()
        assert isinstance(result, list)

    def test_get_header_wordlist_returns_copy(self):
        """Modifying result doesn't affect original."""
        result = get_header_wordlist()
        original_len = len(UNKEYED_HEADERS)

        # Modify the returned list
        result.append("X-Custom-Test-Header")
        result.pop(0)

        # Original should be unchanged
        assert len(UNKEYED_HEADERS) == original_len
        assert "X-Custom-Test-Header" not in UNKEYED_HEADERS

    def test_get_header_wordlist_same_content(self):
        """Returned list has same content as UNKEYED_HEADERS."""
        result = get_header_wordlist()
        assert result == UNKEYED_HEADERS


class TestLoadWordlistFromFile:
    """Tests for load_wordlist_from_file function."""

    def test_load_wordlist_valid(self, tmp_path):
        """Reads entries from file correctly."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("X-Custom-Header\nX-Another-Header\nX-Third\n")
        result = load_wordlist_from_file(str(wordlist_file))
        assert result == ["X-Custom-Header", "X-Another-Header", "X-Third"]

    def test_load_wordlist_skips_empty_lines(self, tmp_path):
        """Blank lines are filtered out."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("X-First\n\n\nX-Second\n\n")
        result = load_wordlist_from_file(str(wordlist_file))
        assert result == ["X-First", "X-Second"]

    def test_load_wordlist_skips_comments(self, tmp_path):
        """Lines starting with # are filtered out."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("# This is a comment\nX-First\n# Another comment\nX-Second\n")
        result = load_wordlist_from_file(str(wordlist_file))
        assert result == ["X-First", "X-Second"]

    def test_load_wordlist_not_found_raises(self):
        """FileNotFoundError raised for missing file."""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_wordlist_from_file("/nonexistent/path/wordlist.txt")
        assert "Wordlist not found" in str(exc_info.value)

    def test_load_wordlist_empty_raises(self, tmp_path):
        """ValueError raised for empty or comment-only file."""
        wordlist_file = tmp_path / "empty.txt"
        wordlist_file.write_text("# Only comments\n# More comments\n")
        with pytest.raises(ValueError) as exc_info:
            load_wordlist_from_file(str(wordlist_file))
        assert "Wordlist is empty" in str(exc_info.value)

    def test_load_wordlist_encoding_errors_ignored(self, tmp_path):
        """Non-UTF8 bytes are handled gracefully."""
        wordlist_file = tmp_path / "headers.txt"
        # Write valid header followed by invalid UTF-8 byte then another valid header
        wordlist_file.write_bytes(b"X-Valid\n\xff\xfeX-Invalid-Line\nX-Another\n")
        result = load_wordlist_from_file(str(wordlist_file))
        # The line with invalid bytes should still be read (errors='ignore' strips bad bytes)
        assert "X-Valid" in result
        assert "X-Another" in result

    def test_load_wordlist_strips_whitespace(self, tmp_path):
        """Leading/trailing whitespace is stripped from entries."""
        wordlist_file = tmp_path / "headers.txt"
        wordlist_file.write_text("  X-First  \n\tX-Second\t\n")
        result = load_wordlist_from_file(str(wordlist_file))
        assert result == ["X-First", "X-Second"]

    def test_load_wordlist_directory_raises(self, tmp_path):
        """ValueError raised when path is a directory, not a file."""
        with pytest.raises(ValueError) as exc_info:
            load_wordlist_from_file(str(tmp_path))
        assert "Not a file" in str(exc_info.value)


class TestGetHeaderWordlistWithCustom:
    """Tests for get_header_wordlist_with_custom function."""

    def test_custom_wordlist_used(self, tmp_path):
        """Custom path returns custom entries."""
        wordlist_file = tmp_path / "custom.txt"
        wordlist_file.write_text("Custom-Header-1\nCustom-Header-2\n")
        result = get_header_wordlist_with_custom(str(wordlist_file))
        assert result == ["Custom-Header-1", "Custom-Header-2"]
        assert result != get_header_wordlist()

    def test_builtin_used_when_no_custom(self):
        """None returns built-in wordlist."""
        result = get_header_wordlist_with_custom(None)
        assert result == get_header_wordlist()
        assert len(result) == 40  # Built-in has 40 headers
