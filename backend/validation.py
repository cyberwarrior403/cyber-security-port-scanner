from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit


class InvalidTargetError(ValueError):
    """Raised when user input is not a valid IPv4 or domain name."""


class DNSResolutionError(RuntimeError):
    """Raised when a valid domain fails DNS resolution."""


@dataclass(frozen=True)
class ValidatedTarget:
    normalized_target: str  # sanitized host (domain or IP)
    resolved_ip: str        # IPv4 string to scan
    is_ip: bool


def _normalize_user_target(raw: Optional[str]) -> str:
    if raw is None:
        raise InvalidTargetError("empty")
    s = raw.strip()
    if not s:
        raise InvalidTargetError("empty")

    # If scheme exists, parse as URL; otherwise parse as //host/path
    # so urlsplit can still extract netloc for inputs like example.com/test.
    if "://" in s:
        parts = urlsplit(s)
    else:
        parts = urlsplit(f"//{s}")

    host = (parts.hostname or "").strip()
    if not host:
        raise InvalidTargetError("missing-host")

    # urlsplit lowercases hostname; keep that.
    host = host.rstrip(".")  # canonicalize FQDN dot
    if not host:
        raise InvalidTargetError("missing-host")

    # Reject bracketed IPv6, we only accept IPv4 per requirements.
    if ":" in host:
        raise InvalidTargetError("ipv6-not-supported")

    return host


def _is_valid_domain_name(hostname: str) -> bool:
    """
    Strict-enough domain validation:
    - requires at least one dot (rejects 'google', 'asdf123')
    - labels: 1-63 chars, alnum/hyphen, not start/end with hyphen
    - total length <= 253
    - TLD must be alpha and length 2-63
    """
    if len(hostname) > 253:
        return False
    if "." not in hostname:
        return False

    labels = hostname.split(".")
    if any(not lbl for lbl in labels):
        return False

    tld = labels[-1]
    if not (2 <= len(tld) <= 63) or not tld.isalpha():
        return False

    for lbl in labels:
        if len(lbl) > 63:
            return False
        if lbl[0] == "-" or lbl[-1] == "-":
            return False
        for ch in lbl:
            if not (ch.isalnum() or ch == "-"):
                return False

    return True


def validate_and_resolve_target(user_input: Optional[str]) -> ValidatedTarget:
    """
    Validates user input as either IPv4 or a fully-qualified domain name.
    Normalizes by removing scheme, paths, query strings, fragments, and ports.

    - IP validation uses `ipaddress` (no regex).
    - Domain resolution uses `socket.gethostbyname()`.
    - Returns resolved IPv4 that must be scanned (never scan raw input).
    """
    host = _normalize_user_target(user_input)

    # 1) Try IPv4
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.version != 4:
            raise InvalidTargetError("ipv6-not-supported")
        return ValidatedTarget(normalized_target=host, resolved_ip=str(ip), is_ip=True)

    # 2) Domain
    if not _is_valid_domain_name(host):
        raise InvalidTargetError("invalid-domain")

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise DNSResolutionError(str(e)) from e

    # Safety: ensure DNS result is IPv4
    try:
        ip2 = ipaddress.ip_address(resolved_ip)
    except ValueError as e:
        raise DNSResolutionError("resolved-to-non-ip") from e
    if ip2.version != 4:
        raise DNSResolutionError("resolved-to-ipv6")

    return ValidatedTarget(normalized_target=host, resolved_ip=str(ip2), is_ip=False)

