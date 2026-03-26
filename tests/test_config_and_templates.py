"""Tests for SSRF protection."""

from __future__ import annotations

import pytest


class TestSSRFSecurity:
    def test_localhost_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://localhost/admin") is False

    def test_127_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://127.0.0.1/secret") is False

    def test_10_network_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://10.0.0.1/api") is False

    def test_172_16_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://172.16.0.1/admin") is False

    def test_192_168_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://192.168.1.1/config") is False

    def test_public_ip_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://93.184.216.34/page") is False

    def test_hostname_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://example.com/page") is False

    def test_allow_internal_env_var(self, monkeypatch):
        from numasec.mcp._security import is_internal_target
        monkeypatch.setenv("NUMASEC_ALLOW_INTERNAL", "1")
        assert is_internal_target("http://127.0.0.1/admin") is False

    def test_allow_internal_true(self, monkeypatch):
        from numasec.mcp._security import is_internal_target
        monkeypatch.setenv("NUMASEC_ALLOW_INTERNAL", "true")
        assert is_internal_target("http://10.0.0.1/api") is False

    def test_ipv6_loopback_allowed(self):
        from numasec.mcp._security import is_internal_target
        assert is_internal_target("http://[::1]/admin") is False
