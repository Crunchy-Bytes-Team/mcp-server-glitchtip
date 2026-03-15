"""Unit tests for IP whitelist (GLITCHTIP_ALLOWED_IPS)."""

from unittest.mock import patch

import pytest

from server import (
    check_allowed_ips_from_env,
    check_ip_allowed,
    parse_allowed_ips,
)


class TestParseAllowedIps:
    def test_empty_or_whitespace_returns_skip(self):
        ok, msg, entries = parse_allowed_ips("")
        assert ok is True
        assert entries == []
        ok, msg, entries = parse_allowed_ips("   ")
        assert ok is True
        assert entries == []

    def test_single_ipv4(self):
        ok, msg, entries = parse_allowed_ips("192.168.1.1")
        assert ok is True
        assert msg == ""
        assert len(entries) == 1
        assert str(entries[0]) == "192.168.1.1"

    def test_cidr(self):
        ok, msg, entries = parse_allowed_ips("10.0.0.0/8")
        assert ok is True
        assert len(entries) == 1
        assert str(entries[0]) == "10.0.0.0/8"

    def test_comma_separated_with_spaces(self):
        ok, msg, entries = parse_allowed_ips(" 192.168.1.1 , 10.0.0.0/8 , 203.0.113.50 ")
        assert ok is True
        assert len(entries) == 3

    def test_invalid_entry_rejected(self):
        ok, msg, entries = parse_allowed_ips("192.168.1.999")
        assert ok is False
        assert "Invalid" in msg or "invalid" in msg
        assert entries == []

    def test_invalid_cidr_rejected(self):
        ok, msg, entries = parse_allowed_ips("10.0.0.0/99")
        assert ok is False
        assert entries == []

    def test_ipv6_rejected(self):
        ok, msg, entries = parse_allowed_ips("::1")
        assert ok is False
        assert "IPv4" in msg or "invalid" in msg.lower()
        ok, msg, entries = parse_allowed_ips("2001:db8::/32")
        assert ok is False


class TestCheckIpAllowed:
    def test_match_single_ip(self):
        import ipaddress
        entries = [ipaddress.ip_address("192.168.1.1")]
        assert check_ip_allowed("192.168.1.1", entries) is True
        assert check_ip_allowed("192.168.1.2", entries) is False

    def test_match_cidr(self):
        import ipaddress
        entries = [ipaddress.ip_network("10.0.0.0/8", strict=False)]
        assert check_ip_allowed("10.1.2.3", entries) is True
        assert check_ip_allowed("192.168.1.1", entries) is False

    def test_invalid_current_ip_returns_false(self):
        import ipaddress
        entries = [ipaddress.ip_address("192.168.1.1")]
        assert check_ip_allowed("not-an-ip", entries) is False
        assert check_ip_allowed("", entries) is False


class TestCheckAllowedIpsFromEnv:
    def test_env_empty_skips_check(self):
        # Unset or empty GLITCHTIP_ALLOWED_IPS skips the check
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": ""}, clear=False):
            allowed, msg = check_allowed_ips_from_env()
            assert allowed is True
            assert msg == ""
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": "   "}, clear=False):
            allowed, msg = check_allowed_ips_from_env()
            assert allowed is True

    def test_current_ip_in_list_allowed(self):
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": "192.168.1.100"}, clear=False):
            with patch("server.get_outbound_ip", return_value="192.168.1.100"):
                allowed, msg = check_allowed_ips_from_env()
                assert allowed is True
                assert msg == ""

    def test_current_ip_in_cidr_allowed(self):
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": "10.0.0.0/8"}, clear=False):
            with patch("server.get_outbound_ip", return_value="10.5.5.5"):
                allowed, msg = check_allowed_ips_from_env()
                assert allowed is True

    def test_current_ip_not_in_list_rejected(self):
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": "192.168.1.1"}, clear=False):
            with patch("server.get_outbound_ip", return_value="203.0.113.50"):
                allowed, msg = check_allowed_ips_from_env()
                assert allowed is False
                assert "203.0.113.50" in msg
                assert "GLITCHTIP_ALLOWED_IPS" in msg

    def test_get_outbound_ip_fails_rejected(self):
        with patch.dict("os.environ", {"GLITCHTIP_ALLOWED_IPS": "192.168.1.1"}, clear=False):
            with patch("server.get_outbound_ip", return_value=None):
                allowed, msg = check_allowed_ips_from_env()
                assert allowed is False
                assert "outbound" in msg.lower() or "determine" in msg.lower()
