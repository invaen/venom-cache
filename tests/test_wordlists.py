"""Tests for wordlists module."""

import pytest

from venom_cache.wordlists import UNKEYED_HEADERS, get_header_wordlist


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
