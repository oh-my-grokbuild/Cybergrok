"""URL scheme, redirect, and address-family guards for probe/crawl."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
IMDS_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}


class UnsafeURL(ValueError):
    pass


def normalize_http_url(raw: str) -> str:
    target = (raw or "").strip()
    if not target:
        raise UnsafeURL("empty URL")
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURL(f"scheme '{parsed.scheme}' is not allowed (http/https only)")
    if not parsed.hostname:
        raise UnsafeURL("URL has no host")
    return target


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> str | None:
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return f"blocked address {ip}"
    if str(ip) in {"169.254.169.254", "::ffff:169.254.169.254"}:
        return "blocked cloud metadata address"
    if ip.is_link_local:
        return f"blocked link-local address {ip}"
    if not allow_private and (ip.is_private or ip.is_loopback):
        return f"blocked private/loopback address {ip}"
    return None


def assert_safe_url(raw: str, *, allow_private: bool = False) -> str:
    target = normalize_http_url(raw)
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if host in IMDS_HOSTS:
        raise UnsafeURL(f"blocked metadata host '{host}'")
    try:
        ip = ipaddress.ip_address(host)
        reason = _is_blocked_ip(ip, allow_private)
        if reason:
            raise UnsafeURL(reason)
        return target
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeURL(f"DNS resolution failed for '{host}': {exc}") from exc
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        reason = _is_blocked_ip(ip, allow_private)
        if reason:
            raise UnsafeURL(f"{reason} (resolved from {host})")
    return target
