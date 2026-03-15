"""Unit tests for validation helpers."""

from unittest.mock import patch

import pytest

from server import (
    normalize_status,
    validate_api_url,
    validate_issue_id,
    validate_slug,
)


class TestValidateIssueId:
    def test_accepts_digits_only(self):
        assert validate_issue_id("123") is True
        assert validate_issue_id("0") is True
        assert validate_issue_id("999999") is True

    def test_rejects_empty(self):
        assert validate_issue_id("") is False
        assert validate_issue_id(None) is False

    def test_rejects_path_traversal(self):
        assert validate_issue_id("../admin") is False
        assert validate_issue_id("123/456") is False
        assert validate_issue_id("123/../../../other") is False

    def test_rejects_spaces_only(self):
        assert validate_issue_id("   ") is False
        assert validate_issue_id(" 123 ") is True  # strip makes it valid

    def test_rejects_non_numeric(self):
        assert validate_issue_id("abc") is False
        assert validate_issue_id("12a") is False
        assert validate_issue_id("12.3") is False


class TestValidateSlug:
    def test_accepts_valid_slugs(self):
        assert validate_slug("my-org") is True
        assert validate_slug("my_org") is True
        assert validate_slug("org123") is True
        assert validate_slug("a") is True

    def test_rejects_path_separators(self):
        assert validate_slug("a/b") is False
        assert validate_slug("a\\b") is False
        assert validate_slug("..") is False

    def test_rejects_empty(self):
        assert validate_slug("") is False
        assert validate_slug(None) is False

    def test_rejects_percent_and_newline(self):
        assert validate_slug("org%20name") is False
        assert validate_slug("org\nname") is False


class TestNormalizeStatus:
    def test_accepts_allowed_values(self):
        assert normalize_status("unresolved") == "unresolved"
        assert normalize_status("resolved") == "resolved"
        assert normalize_status("ignored") == "ignored"

    def test_falls_back_to_unresolved_for_unknown(self):
        assert normalize_status("invalid") == "unresolved"
        assert normalize_status("") == "unresolved"
        assert normalize_status(None) == "unresolved"
        assert normalize_status("UNRESOLVED") == "unresolved"  # case-sensitive


class TestValidateApiUrl:
    def test_accepts_https_with_host(self):
        # Use a known public hostname that won't resolve to private IP
        ok, msg = validate_api_url("https://glitchtip.example.com/api/0/")
        assert ok is True, msg
        assert msg == ""

    def test_rejects_empty(self):
        ok, msg = validate_api_url("")
        assert ok is False
        assert "empty" in msg.lower()

    def test_rejects_wrong_scheme(self):
        ok, msg = validate_api_url("ftp://example.com/")
        assert ok is False
        assert "http" in msg.lower()

    def test_rejects_http_non_localhost(self):
        ok, msg = validate_api_url("http://example.com/api/0/")
        assert ok is False
        assert "localhost" in msg.lower() or "https" in msg.lower()

    def test_accepts_http_localhost(self):
        ok, msg = validate_api_url("http://localhost/api/0/")
        assert ok is True, msg

    def test_accepts_http_127_0_0_1(self):
        ok, msg = validate_api_url("http://127.0.0.1/api/0/")
        assert ok is True, msg

    def test_accepts_https_localhost(self):
        ok, msg = validate_api_url("https://localhost/api/0/")
        assert ok is True, msg

    def test_rejects_https_private_ip(self):
        with patch("server._is_private_or_metadata_ip", return_value=True):
            ok, msg = validate_api_url("https://internal.corp/api/0/")
            assert ok is False
            assert "private" in msg.lower() or "metadata" in msg.lower()

    def test_rejects_metadata_ip(self):
        # 169.254.169.254 is common metadata endpoint; patch where server uses it
        with patch("server._is_private_or_metadata_ip", return_value=True):
            ok, msg = validate_api_url("https://169.254.169.254/")
            assert ok is False
            assert "private" in msg.lower() or "metadata" in msg.lower()