"""Tests for baseline response capture and comparison."""

import pytest

from venom_cache.baseline import (
    ResponseBaseline,
    ResponseDiff,
    compare_response,
    strip_dynamic_content,
)


class TestStripDynamicContent:
    """Tests for dynamic content stripping."""

    def test_strip_iso_timestamp(self):
        body = b'{"timestamp": "2024-01-29T10:30:00", "data": "hello"}'
        result = strip_dynamic_content(body)
        assert b"2024-01-29T10:30:00" not in result
        assert b"__DYNAMIC__" in result
        assert b'"data": "hello"' in result

    def test_strip_unix_timestamp(self):
        body = b'{"time": 1706523000, "data": "test"}'
        result = strip_dynamic_content(body)
        assert b"1706523000" not in result
        assert b"__DYNAMIC__" in result

    def test_strip_uuid(self):
        body = b'{"id": "550e8400-e29b-41d4-a716-446655440000"}'
        result = strip_dynamic_content(body)
        assert b"550e8400-e29b-41d4-a716-446655440000" not in result
        assert b"__DYNAMIC__" in result

    def test_strip_csrf_token(self):
        # CSRF tokens in JSON format (common in API responses)
        body = b'{"csrf_token": "abc123def456ghi789jkl012"}'
        result = strip_dynamic_content(body)
        assert b"abc123def456ghi789jkl012" not in result

    def test_no_dynamic_content(self):
        body = b"<html><body>Hello World</body></html>"
        result = strip_dynamic_content(body)
        assert result == body  # No change

    def test_multiple_dynamic_values(self):
        body = b'{"ts1": "2024-01-29T10:00:00", "ts2": "2024-01-29T11:00:00"}'
        result = strip_dynamic_content(body)
        assert result.count(b"__DYNAMIC__") == 2


class TestCompareResponseIdentical:
    """Tests for comparing identical responses."""

    def test_identical_response(self):
        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={"Content-Type": "text/html"},
            body_hash="abc123",
            body_length=100,
            content_type="text/html",
            static_body_hash="def456",
            captured_at=1000.0,
        )

        diff = compare_response(
            baseline,
            status=200,
            headers={"Content-Type": "text/html"},
            body=b"x" * 100,  # Will have different hash but we control that below
        )

        assert diff.status_changed is False
        assert diff.headers_changed == []


class TestCompareResponseDynamic:
    """Tests for dynamic content handling in comparison."""

    def test_only_timestamp_changes(self):
        """Dynamic content changes should not be significant."""
        body1 = b'{"time": "2024-01-29T10:00:00", "data": "same"}'
        body2 = b'{"time": "2024-01-29T11:00:00", "data": "same"}'

        # Create baseline from body1
        from venom_cache.baseline import _hash_body, strip_dynamic_content

        static1 = strip_dynamic_content(body1)
        static2 = strip_dynamic_content(body2)

        # Static bodies should be identical after stripping timestamps
        assert _hash_body(static1) == _hash_body(static2)

        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash=_hash_body(body1),
            body_length=len(body1),
            content_type=None,
            static_body_hash=_hash_body(static1),
            captured_at=1000.0,
        )

        diff = compare_response(baseline, status=200, headers={}, body=body2)

        # Raw body changed, but static body should be the same
        assert diff.body_changed is True
        assert diff.static_body_changed is False
        assert diff.significant is False


class TestCompareResponseSignificant:
    """Tests for detecting significant changes."""

    def test_status_code_change(self):
        from venom_cache.baseline import _hash_body

        body = b"test body"
        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash=_hash_body(body),
            body_length=len(body),
            content_type=None,
            static_body_hash=_hash_body(body),
            captured_at=1000.0,
        )

        diff = compare_response(baseline, status=404, headers={}, body=body)

        assert diff.status_changed is True
        assert diff.significant is True

    def test_body_content_change(self):
        from venom_cache.baseline import _hash_body, strip_dynamic_content

        body1 = b"original content"
        body2 = b"modified content"

        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash=_hash_body(body1),
            body_length=len(body1),
            content_type=None,
            static_body_hash=_hash_body(strip_dynamic_content(body1)),
            captured_at=1000.0,
        )

        diff = compare_response(baseline, status=200, headers={}, body=body2)

        assert diff.body_changed is True
        assert diff.static_body_changed is True
        assert diff.significant is True


class TestCompareResponseHeaders:
    """Tests for header comparison."""

    def test_date_header_change_not_significant(self):
        """Date header is volatile and should not cause significance."""
        from venom_cache.baseline import _hash_body

        body = b"test"
        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={"Date": "Mon, 29 Jan 2024 10:00:00 GMT"},
            body_hash=_hash_body(body),
            body_length=len(body),
            content_type=None,
            static_body_hash=_hash_body(body),
            captured_at=1000.0,
        )

        diff = compare_response(
            baseline,
            status=200,
            headers={"Date": "Mon, 29 Jan 2024 11:00:00 GMT"},
            body=body,
        )

        # Date is volatile, so should not appear in headers_changed
        assert "date" not in diff.headers_changed
        assert diff.significant is False

    def test_custom_header_change_significant(self):
        """Non-volatile header changes should be significant."""
        from venom_cache.baseline import _hash_body

        body = b"test"
        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={"X-Custom": "value1"},
            body_hash=_hash_body(body),
            body_length=len(body),
            content_type=None,
            static_body_hash=_hash_body(body),
            captured_at=1000.0,
        )

        diff = compare_response(
            baseline,
            status=200,
            headers={"X-Custom": "value2"},
            body=body,
        )

        assert "x-custom" in diff.headers_changed
        assert diff.significant is True


class TestContentLengthDelta:
    """Tests for content length tracking."""

    def test_content_length_increase(self):
        from venom_cache.baseline import _hash_body

        body1 = b"short"
        body2 = b"much longer body"

        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash=_hash_body(body1),
            body_length=len(body1),
            content_type=None,
            static_body_hash=_hash_body(body1),
            captured_at=1000.0,
        )

        diff = compare_response(baseline, status=200, headers={}, body=body2)

        assert diff.content_length_delta == len(body2) - len(body1)
        assert diff.content_length_delta > 0

    def test_content_length_decrease(self):
        from venom_cache.baseline import _hash_body

        body1 = b"longer body here"
        body2 = b"short"

        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash=_hash_body(body1),
            body_length=len(body1),
            content_type=None,
            static_body_hash=_hash_body(body1),
            captured_at=1000.0,
        )

        diff = compare_response(baseline, status=200, headers={}, body=body2)

        assert diff.content_length_delta < 0
