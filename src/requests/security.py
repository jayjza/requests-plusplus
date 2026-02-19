"""
requests.security
~~~~~~~~~~~~~~~~~

SSRF (Server-Side Request Forgery) and DNS rebinding protection.

Provides :class:`SSRFValidator` for configuring blocked/allowed IP ranges, and
:class:`SSRFProtectedHTTPAdapter` (in ``adapters.py``) for applying that protection
to a ``requests.Session``.

How it works
------------
When this module is first imported, it patches ``urllib3.util.connection.create_connection``
(the function urllib3 actually calls to open TCP sockets) with a thread-local-aware wrapper.
The wrapper is a no-op unless an :class:`SSRFValidator` is stored in the thread-local for
the current request (set by :class:`SSRFProtectedHTTPAdapter`).

When a validator IS active the wrapper:

1. Resolves the hostname via ``socket.getaddrinfo`` (once).
2. Validates **every** resolved IP against the validator's blocked/allowed ranges.
3. Connects directly to the first validated ``(host, port)`` sockaddr tuple **without
   re-resolving the hostname**.  This single-resolution approach is what prevents DNS
   rebinding — an attacker cannot swap in a private IP between validation and connect.

IPv4-mapped IPv6 addresses (e.g. ``::ffff:192.168.1.1``) are unwrapped to their IPv4
form before range checks so that private IPv4 ranges always match.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import typing

__all__ = [
    "DEFAULT_BLOCKED_RANGES",
    "SSRFValidator",
]

# Thread-local storage: holds the active SSRFValidator for the current thread's request.
# None means no SSRF protection is active (behaves like the original urllib3 code).
_ssrf_validator_local: threading.local = threading.local()


# ---------------------------------------------------------------------------
# Internal signal class
# ---------------------------------------------------------------------------

class _SSRFViolationSignal(BaseException):
    """Internal sentinel raised at the socket level when SSRF protection blocks a connection.

    Inherits from ``BaseException`` (not ``Exception``) so that it propagates
    through urllib3's broad ``except Exception`` clauses without being swallowed.
    :class:`SSRFProtectedHTTPAdapter` catches it and converts it to the public
    :exc:`~requests.exceptions.SSRFViolation`.
    """


# ---------------------------------------------------------------------------
# Default blocked IP ranges
# ---------------------------------------------------------------------------

#: Default set of IP networks blocked by :class:`SSRFValidator`.
#:
#: Covers all RFC-reserved, private, loopback, link-local, documentation, and
#: multicast ranges for both IPv4 and IPv6.  Notable inclusions:
#:
#: * ``169.254.0.0/16`` — Link-local; includes the AWS EC2 instance metadata
#:   service at ``169.254.169.254``.
#: * ``fc00::/7`` — IPv6 unique-local (the RFC 4193 equivalent of RFC 1918).
#: * ``2001::/32`` — Teredo; can tunnel IPv4 traffic through IPv6 and may
#:   reach private IPv4 ranges.
DEFAULT_BLOCKED_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # ---- IPv4 ----
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space / carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local — includes AWS IMDS (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 1112)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast
    # ---- IPv6 ----
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation / NAT64 (RFC 6052)
    ipaddress.ip_network("100::/64"),           # Discard-only address block (RFC 6666)
    ipaddress.ip_network("2001::/32"),          # Teredo tunneling (RFC 4380)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique-local / private (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-local (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]


# ---------------------------------------------------------------------------
# SSRFValidator
# ---------------------------------------------------------------------------

class SSRFValidator:
    """Validates resolved IP addresses against configurable blocked/allowed ranges.

    :param blocked_ranges:
        Iterable of :class:`~ipaddress.IPv4Network` / :class:`~ipaddress.IPv6Network`
        objects to block.  Defaults to :data:`DEFAULT_BLOCKED_RANGES`.
    :param allowed_ranges:
        Iterable of networks that are **always** permitted, even if they also
        appear in *blocked_ranges*.  Useful for allowing a specific internal
        network while keeping the rest of RFC 1918 blocked.

    Usage::

        from ipaddress import ip_network
        from requests.security import SSRFValidator

        # Allow one specific internal subnet, block everything else private
        validator = SSRFValidator(
            allowed_ranges=[ip_network("10.0.1.0/24")],
        )
    """

    #: The default blocked ranges used when no *blocked_ranges* argument is given.
    DEFAULT_BLOCKED_RANGES = DEFAULT_BLOCKED_RANGES

    def __init__(
        self,
        blocked_ranges: typing.Optional[
            typing.Collection[ipaddress.IPv4Network | ipaddress.IPv6Network]
        ] = None,
        allowed_ranges: typing.Optional[
            typing.Collection[ipaddress.IPv4Network | ipaddress.IPv6Network]
        ] = None,
    ) -> None:
        self.blocked_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
            list(blocked_ranges) if blocked_ranges is not None else DEFAULT_BLOCKED_RANGES
        )
        self.allowed_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
            list(allowed_ranges) if allowed_ranges is not None else []
        )

    def is_ip_blocked(self, ip_str: str) -> bool:
        """Return ``True`` if *ip_str* should be blocked.

        IPv4-mapped IPv6 addresses (``::ffff:<v4>``) are automatically unwrapped
        so that IPv4 block ranges match correctly.
        """
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip_str)
        except ValueError:
            # Unparseable address — block it to be safe.
            return True

        # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 → 192.168.1.1) so
        # that IPv4 private ranges always trigger.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped

        # Allowlist takes priority over blocklist.
        for allowed in self.allowed_ranges:
            if ip in allowed:
                return False

        for blocked in self.blocked_ranges:
            if ip in blocked:
                return True

        return False

    def validate_ip(self, ip_str: str) -> None:
        """Raise :exc:`_SSRFViolationSignal` if *ip_str* is blocked.

        Called from the patched urllib3 ``create_connection`` wrapper for every
        IP address returned by DNS resolution before any socket is opened.
        """
        if self.is_ip_blocked(ip_str):
            raise _SSRFViolationSignal(
                f"Blocked connection to {ip_str!r}: address is in a reserved/private range. "
                f"Use SSRFValidator(allowed_ranges=[...]) to permit specific internal addresses."
            )


# ---------------------------------------------------------------------------
# urllib3 create_connection patch
# ---------------------------------------------------------------------------

def _install_ssrf_hook() -> None:
    """Patch ``urllib3.util.connection.create_connection`` with an SSRF-aware wrapper.

    The patch is installed once at module import time.  It is a no-op when no
    :class:`SSRFValidator` is active in the current thread, so it has no
    observable effect on code that does not use :class:`SSRFProtectedHTTPAdapter`.
    """
    try:
        import urllib3.util.connection as _urllib3_conn
    except ImportError:
        return  # urllib3 not installed; nothing to patch.

    _original = _urllib3_conn.create_connection

    # Grab urllib3-internal helpers at patch time so the wrapper is self-contained.
    try:
        from urllib3.util.connection import allowed_gai_family as _allowed_gai_family
        from urllib3.util.timeout import _DEFAULT_TIMEOUT as _urllib3_default_timeout
    except ImportError:
        # Older urllib3 versions may not export these names.  Fall back to sane
        # defaults: always try both address families, never set a timeout sentinel.
        _allowed_gai_family = lambda: socket.AF_UNSPEC  # noqa: E731
        _urllib3_default_timeout = None

    def _ssrf_aware_create_connection(
        address: tuple[str, int],
        timeout: typing.Any = _urllib3_default_timeout,
        source_address: tuple[str, int] | None = None,
        socket_options: typing.Any = None,
    ) -> socket.socket:
        validator: SSRFValidator | None = getattr(_ssrf_validator_local, "validator", None)

        if validator is None:
            # Fast path: no SSRF protection active — call the real urllib3 function.
            return _original(address, timeout, source_address, socket_options)

        host, port = address

        # urllib3 strips brackets from IPv6 literals.
        if host.startswith("["):
            host = host.strip("[]")

        # Replicate urllib3's IDNA validation.
        try:
            host.encode("idna")
        except UnicodeError:
            try:
                from urllib3.exceptions import LocationParseError
                raise LocationParseError(
                    f"'{host}', label empty or too long"
                ) from None
            except ImportError:
                raise OSError(f"Invalid hostname: '{host}', label empty or too long") from None

        family = _allowed_gai_family()

        # --- Phase 1: resolve ---
        addrinfos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)

        if not addrinfos:
            raise OSError("getaddrinfo returns an empty list")

        # --- Phase 2: validate ALL resolved IPs before touching a socket ---
        # Raising here prevents any connection attempt to a blocked address.
        for _af, _socktype, _proto, _canonname, sa in addrinfos:
            validator.validate_ip(sa[0])

        # --- Phase 3: connect directly to a validated sockaddr (no re-resolution) ---
        # By connecting to the ``sa`` tuple we already resolved we avoid re-querying
        # DNS, which is the key defence against DNS rebinding attacks.
        err: OSError | None = None
        for af, socktype, proto, _canonname, sa in addrinfos:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(af, socktype, proto)

                # Apply socket options the same way urllib3 does.
                if socket_options is not None:
                    for opt in socket_options:
                        sock.setsockopt(*opt)

                if timeout is not _urllib3_default_timeout:
                    sock.settimeout(timeout)

                if source_address:
                    sock.bind(source_address)

                sock.connect(sa)
                # Clear the reference cycle (mirrors urllib3's own cleanup).
                err = None
                return sock

            except OSError as exc:
                err = exc
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        raise OSError("getaddrinfo returns an empty list")

    _urllib3_conn.create_connection = _ssrf_aware_create_connection


_install_ssrf_hook()
