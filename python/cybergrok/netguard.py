"""URL scheme, redirect, and address-family guards for probe/crawl."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

ALLOWED_SCHEMES = {"http", "https"}
IMDS_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
    "100.100.100.200",
    "fd00:ec2::254",
    "168.63.129.16",
}
IMDS_NETWORKS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("168.63.129.16/32"),
)


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


def _canonical_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> str | None:
    ip = _canonical_ip(ip)
    if any(ip in net for net in IMDS_NETWORKS):
        return "blocked cloud metadata address"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return f"blocked address {ip}"
    if ip.is_link_local:
        return f"blocked link-local address {ip}"
    if not allow_private and (ip.is_private or ip.is_loopback):
        return f"blocked private/loopback address {ip}"
    return None


def _pin_url(target: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    parsed = urlparse(target)
    ip = _canonical_ip(ip)
    host = str(ip)
    netloc = f"[{host}]" if ":" in host else host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _checked_ips(host: str, port: int, allow_private: bool) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeURL(f"DNS resolution failed for '{host}': {exc}") from exc
    if not infos:
        raise UnsafeURL(f"DNS resolution returned no addresses for '{host}'")
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        reason = _is_blocked_ip(ip, allow_private)
        if reason:
            raise UnsafeURL(f"{reason} (resolved from {host})")
        ips.append(ip)
    if not ips:
        raise UnsafeURL(f"DNS resolution returned no usable addresses for '{host}'")
    return ips


def assert_safe_url(raw: str, *, allow_private: bool = False) -> str:
    target, _host = prepare_safe_request(raw, allow_private=allow_private)
    return target


def prepare_safe_request(raw: str, *, allow_private: bool = False) -> tuple[str, str]:
    """Return (pinned fetch URL, Host header). Connects to the checked IP only."""
    target = normalize_http_url(raw)
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if host in IMDS_HOSTS:
        raise UnsafeURL(f"blocked metadata host '{host}'")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host_header = f"{host}:{parsed.port}" if parsed.port and parsed.port not in {80, 443} else host
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        reason = _is_blocked_ip(literal_ip, allow_private)
        if reason:
            raise UnsafeURL(reason)
        return target, host_header
    ips = _checked_ips(host, port, allow_private)
    return _pin_url(target, ips[0]), host_header
