"""
Tests for SSRF and DNS rebinding protection.

Covers:
- SSRFValidator.is_ip_blocked / validate_ip
- IPv4-mapped IPv6 address unwrapping
- Allowlist overrides
- Custom blocked_ranges
- SSRFProtectedHTTPAdapter: IP-literal URLs blocked pre-DNS
- SSRFProtectedHTTPAdapter: thread-local validator cleared after send()
- SSRFProtectedHTTPAdapter: pickling support
- urllib3 create_connection patch: no-op when no validator is active
"""

from __future__ import annotations

import ipaddress
import pickle
import socket
import threading
import typing
import unittest
from unittest.mock import MagicMock, patch

import pytest

import requests
from requests.adapters import SSRFProtectedHTTPAdapter
from requests.exceptions import SSRFViolation
from requests.security import (
    DEFAULT_BLOCKED_RANGES,
    SSRFValidator,
    _SSRFViolationSignal,
    _ssrf_validator_local,
)


# ---------------------------------------------------------------------------
# SSRFValidator unit tests
# ---------------------------------------------------------------------------


class TestSSRFValidatorDefaults:
    """SSRFValidator with default blocked ranges."""

    def setup_method(self):
        self.validator = SSRFValidator()

    # --- loopback ---
    def test_ipv4_loopback_blocked(self):
        assert self.validator.is_ip_blocked("127.0.0.1")

    def test_ipv4_loopback_other_blocked(self):
        assert self.validator.is_ip_blocked("127.255.255.254")

    def test_ipv6_loopback_blocked(self):
        assert self.validator.is_ip_blocked("::1")

    # --- RFC 1918 private ---
    def test_private_10_blocked(self):
        assert self.validator.is_ip_blocked("10.0.0.1")

    def test_private_172_16_blocked(self):
        assert self.validator.is_ip_blocked("172.16.0.1")

    def test_private_172_31_blocked(self):
        assert self.validator.is_ip_blocked("172.31.255.254")

    def test_private_192_168_blocked(self):
        assert self.validator.is_ip_blocked("192.168.1.100")

    # --- link-local (includes AWS IMDS) ---
    def test_link_local_aws_imds_blocked(self):
        assert self.validator.is_ip_blocked("169.254.169.254")

    def test_link_local_ipv4_blocked(self):
        assert self.validator.is_ip_blocked("169.254.0.1")

    def test_link_local_ipv6_blocked(self):
        assert self.validator.is_ip_blocked("fe80::1")

    # --- unique-local IPv6 (private equivalent) ---
    def test_ipv6_unique_local_fc_blocked(self):
        assert self.validator.is_ip_blocked("fc00::1")

    def test_ipv6_unique_local_fd_blocked(self):
        assert self.validator.is_ip_blocked("fd12:3456:789a::1")

    # --- shared address space ---
    def test_carrier_grade_nat_blocked(self):
        assert self.validator.is_ip_blocked("100.64.0.1")

    # --- multicast ---
    def test_multicast_ipv4_blocked(self):
        assert self.validator.is_ip_blocked("224.0.0.1")

    def test_multicast_ipv6_blocked(self):
        assert self.validator.is_ip_blocked("ff02::1")

    # --- reserved ---
    def test_reserved_240_blocked(self):
        assert self.validator.is_ip_blocked("240.0.0.1")

    def test_broadcast_blocked(self):
        assert self.validator.is_ip_blocked("255.255.255.255")

    # --- documentation ranges ---
    def test_documentation_192_0_2_blocked(self):
        assert self.validator.is_ip_blocked("192.0.2.1")

    def test_documentation_198_51_blocked(self):
        assert self.validator.is_ip_blocked("198.51.100.1")

    def test_documentation_203_0_113_blocked(self):
        assert self.validator.is_ip_blocked("203.0.113.1")

    def test_documentation_ipv6_blocked(self):
        assert self.validator.is_ip_blocked("2001:db8::1")

    # --- public IPs are allowed ---
    def test_public_ipv4_not_blocked(self):
        assert not self.validator.is_ip_blocked("1.1.1.1")

    def test_google_dns_not_blocked(self):
        assert not self.validator.is_ip_blocked("8.8.8.8")

    def test_public_ipv6_not_blocked(self):
        assert not self.validator.is_ip_blocked("2606:4700:4700::1111")


class TestSSRFValidatorIPv4MappedIPv6:
    """IPv4-mapped IPv6 addresses are unwrapped before range checks."""

    def setup_method(self):
        self.validator = SSRFValidator()

    def test_ipv4_mapped_loopback_blocked(self):
        assert self.validator.is_ip_blocked("::ffff:127.0.0.1")

    def test_ipv4_mapped_private_blocked(self):
        assert self.validator.is_ip_blocked("::ffff:192.168.1.1")

    def test_ipv4_mapped_link_local_blocked(self):
        assert self.validator.is_ip_blocked("::ffff:169.254.169.254")

    def test_ipv4_mapped_public_not_blocked(self):
        assert not self.validator.is_ip_blocked("::ffff:1.1.1.1")

    def test_ipv4_mapped_public_google_not_blocked(self):
        assert not self.validator.is_ip_blocked("::ffff:8.8.8.8")


class TestSSRFValidatorAllowlist:
    """Allowlist overrides the blocklist."""

    def test_allowlist_permits_private_ip(self):
        validator = SSRFValidator(
            allowed_ranges=[ipaddress.ip_network("10.0.1.0/24")],
        )
        assert not validator.is_ip_blocked("10.0.1.50")

    def test_allowlist_does_not_affect_other_private(self):
        validator = SSRFValidator(
            allowed_ranges=[ipaddress.ip_network("10.0.1.0/24")],
        )
        assert validator.is_ip_blocked("10.0.2.1")

    def test_allowlist_permits_loopback(self):
        validator = SSRFValidator(
            allowed_ranges=[ipaddress.ip_network("127.0.0.1/32")],
        )
        assert not validator.is_ip_blocked("127.0.0.1")
        # Other loopback IPs still blocked
        assert validator.is_ip_blocked("127.0.0.2")

    def test_allowlist_ipv6(self):
        validator = SSRFValidator(
            allowed_ranges=[ipaddress.ip_network("fd00::/120")],
        )
        assert not validator.is_ip_blocked("fd00::1")
        assert validator.is_ip_blocked("fd00::200")


class TestSSRFValidatorCustomBlockedRanges:
    """Custom blocked_ranges replaces the defaults entirely."""

    def test_custom_blocked_only_blocks_specified(self):
        validator = SSRFValidator(
            blocked_ranges=[ipaddress.ip_network("192.168.0.0/16")],
        )
        # Specified range is blocked
        assert validator.is_ip_blocked("192.168.1.1")
        # Other private ranges are NOT blocked when using custom ranges
        assert not validator.is_ip_blocked("10.0.0.1")
        assert not validator.is_ip_blocked("127.0.0.1")

    def test_empty_blocked_ranges_allows_everything(self):
        validator = SSRFValidator(blocked_ranges=[])
        assert not validator.is_ip_blocked("127.0.0.1")
        assert not validator.is_ip_blocked("192.168.1.1")


class TestSSRFValidatorValidateIp:
    """validate_ip raises _SSRFViolationSignal for blocked IPs."""

    def setup_method(self):
        self.validator = SSRFValidator()

    def test_validate_blocked_raises(self):
        with pytest.raises(_SSRFViolationSignal):
            self.validator.validate_ip("127.0.0.1")

    def test_validate_public_does_not_raise(self):
        self.validator.validate_ip("1.1.1.1")  # should not raise

    def test_validate_invalid_ip_raises(self):
        with pytest.raises(_SSRFViolationSignal):
            self.validator.validate_ip("not-an-ip")


# ---------------------------------------------------------------------------
# SSRFProtectedHTTPAdapter unit tests (no real network)
# ---------------------------------------------------------------------------


class TestSSRFProtectedHTTPAdapterIPLiteral:
    """IP literals in the URL are rejected before any DNS lookup."""

    def _adapter_send(self, url: str, **kwargs):
        adapter = SSRFProtectedHTTPAdapter()
        req = requests.Request("GET", url).prepare()
        return adapter.send(req, **kwargs)

    def test_loopback_ip_literal_blocked(self):
        with pytest.raises(SSRFViolation):
            self._adapter_send("http://127.0.0.1/")

    def test_private_ip_literal_blocked(self):
        with pytest.raises(SSRFViolation):
            self._adapter_send("http://192.168.1.1/")

    def test_link_local_ip_literal_blocked(self):
        with pytest.raises(SSRFViolation):
            self._adapter_send("http://169.254.169.254/")

    def test_ipv6_loopback_literal_blocked(self):
        with pytest.raises(SSRFViolation):
            self._adapter_send("http://[::1]/")

    def test_ipv6_private_literal_blocked(self):
        with pytest.raises(SSRFViolation):
            self._adapter_send("http://[fc00::1]/")


class TestSSRFProtectedHTTPAdapterThreadLocal:
    """Thread-local validator is cleared after send() regardless of outcome."""

    def test_validator_cleared_on_success(self):
        adapter = SSRFProtectedHTTPAdapter()
        req = requests.Request("GET", "http://1.1.1.1/").prepare()

        # Patch super().send() to succeed immediately
        with patch.object(SSRFProtectedHTTPAdapter, "send", wraps=adapter.send) as _:
            with patch("requests.adapters.HTTPAdapter.send", return_value=MagicMock()):
                adapter.send(req)

        assert getattr(_ssrf_validator_local, "validator", None) is None

    def test_validator_cleared_on_ssrf_violation(self):
        adapter = SSRFProtectedHTTPAdapter()
        req = requests.Request("GET", "http://127.0.0.1/").prepare()

        with pytest.raises(SSRFViolation):
            adapter.send(req)

        assert getattr(_ssrf_validator_local, "validator", None) is None

    def test_validator_cleared_on_other_exception(self):
        adapter = SSRFProtectedHTTPAdapter()
        req = requests.Request("GET", "http://1.1.1.1/").prepare()

        with patch(
            "requests.adapters.HTTPAdapter.send",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(RuntimeError):
                adapter.send(req)

        assert getattr(_ssrf_validator_local, "validator", None) is None


class TestSSRFProtectedHTTPAdapterCustomValidator:
    """Custom validator and allowed_ranges are respected."""

    def test_custom_validator_accepted(self):
        validator = SSRFValidator(blocked_ranges=[])
        adapter = SSRFProtectedHTTPAdapter(validator=validator)
        assert adapter.ssrf_validator is validator

    def test_allowed_ranges_passed_through(self):
        allowed = [ipaddress.ip_network("127.0.0.1/32")]
        adapter = SSRFProtectedHTTPAdapter(allowed_ranges=allowed)
        assert adapter.ssrf_validator.allowed_ranges == allowed

    def test_blocked_ranges_passed_through(self):
        blocked = [ipaddress.ip_network("192.168.0.0/16")]
        adapter = SSRFProtectedHTTPAdapter(blocked_ranges=blocked)
        assert adapter.ssrf_validator.blocked_ranges == blocked

    def test_allowed_range_permits_private_ip_literal(self):
        """When the private IP is explicitly allowed, no SSRFViolation is raised."""
        adapter = SSRFProtectedHTTPAdapter(
            allowed_ranges=[ipaddress.ip_network("192.168.1.0/24")],
        )
        req = requests.Request("GET", "http://192.168.1.50/").prepare()

        # The IP-literal check passes; super().send() will then fail with a
        # real ConnectionError (no server), which we allow through.
        with patch(
            "requests.adapters.HTTPAdapter.send",
            return_value=MagicMock(),
        ):
            adapter.send(req)  # should not raise SSRFViolation


class TestSSRFProtectedHTTPAdapterPickle:
    """SSRFProtectedHTTPAdapter can be pickled and unpickled."""

    def test_round_trip_default(self):
        adapter = SSRFProtectedHTTPAdapter()
        restored = pickle.loads(pickle.dumps(adapter))
        assert isinstance(restored.ssrf_validator, SSRFValidator)
        assert restored.ssrf_validator.blocked_ranges == DEFAULT_BLOCKED_RANGES

    def test_round_trip_custom_ranges(self):
        blocked = [ipaddress.ip_network("10.0.0.0/8")]
        adapter = SSRFProtectedHTTPAdapter(blocked_ranges=blocked)
        restored = pickle.loads(pickle.dumps(adapter))
        assert restored.ssrf_validator.blocked_ranges == blocked


# ---------------------------------------------------------------------------
# urllib3 patch smoke test
# ---------------------------------------------------------------------------


class TestUrllib3PatchNoOp:
    """The patched create_connection is a no-op when no validator is active."""

    def test_no_validator_calls_original(self):
        """With no validator in thread-local, the patch delegates to urllib3's original."""
        import urllib3.util.connection as _urllib3_conn

        # Ensure no validator is set
        _ssrf_validator_local.validator = None

        original_called = []
        _real_original = _urllib3_conn.create_connection

        def _fake_original(address, timeout=None, source_address=None, socket_options=None):
            original_called.append(address)
            # Return a mock socket so we don't open a real connection.
            return MagicMock(spec=socket.socket)

        # Temporarily replace the underlying original that the patch delegates to.
        # We do this by setting a validator to None, which means the patched
        # function should call through.  We verify it reaches our fake.
        with patch.object(_urllib3_conn, "create_connection", _fake_original):
            # Re-install the hook so it wraps our fake original.
            from requests.security import _install_ssrf_hook

            _install_ssrf_hook()

            # Call with no validator — should reach _fake_original.
            sock = _urllib3_conn.create_connection(("example.com", 80))
            assert original_called == [("example.com", 80)]

        # Reinstall the hook wrapping the real original.
        _install_ssrf_hook()


# ---------------------------------------------------------------------------
# Integration-style: SSRFViolation is a ConnectionError subclass
# ---------------------------------------------------------------------------


class TestSSRFViolationExceptionHierarchy:
    def test_is_connection_error(self):
        exc = SSRFViolation("blocked")
        assert isinstance(exc, requests.exceptions.ConnectionError)

    def test_is_request_exception(self):
        exc = SSRFViolation("blocked")
        assert isinstance(exc, requests.exceptions.RequestException)

    def test_carries_request(self):
        req = requests.Request("GET", "http://127.0.0.1/").prepare()
        exc = SSRFViolation("blocked", request=req)
        assert exc.request is req


# ---------------------------------------------------------------------------
# Public API availability
# ---------------------------------------------------------------------------


class TestPublicAPI:
    def test_ssrf_protected_adapter_importable(self):
        from requests import SSRFProtectedHTTPAdapter as A  # noqa: F401

    def test_ssrf_violation_importable(self):
        from requests import SSRFViolation as E  # noqa: F401

    def test_ssrf_validator_importable(self):
        from requests import SSRFValidator as V  # noqa: F401

    def test_default_blocked_ranges_importable(self):
        from requests import DEFAULT_BLOCKED_RANGES as R  # noqa: F401
        assert len(R) > 0
