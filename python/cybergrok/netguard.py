"""URL scheme, redirect, and address-family guards for probe/crawl."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import final, override
from urllib.parse import urlparse
from urllib.request import (
    BaseHandler,
    HTTPHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

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


@dataclass(frozen=True)
class SafeRequest:
    """Checked request: keep the hostname URL, connect to the resolved IP."""

    url: str
    connect_host: str
    port: int
    host_header: str
    server_name: str


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


def _canonical_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    mapped = getattr(ip, "ipv4_mapped", None)
    if isinstance(mapped, ipaddress.IPv4Address):
        return mapped
    return ip


def _is_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool
) -> str | None:
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


def _format_connect_host(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return str(_canonical_ip(ip))


def _checked_ips(
    host: str, port: int, allow_private: bool
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
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
    return prepare_safe_request(raw, allow_private=allow_private).url


def prepare_safe_request(raw: str, *, allow_private: bool = False) -> SafeRequest:
    """Check the URL, then connect to the resolved IP while keeping the hostname URL."""
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
        return SafeRequest(
            url=target,
            connect_host=_format_connect_host(literal_ip),
            port=port,
            host_header=host_header,
            server_name=host,
        )
    ip = _checked_ips(host, port, allow_private)[0]
    return SafeRequest(
        url=target,
        connect_host=_format_connect_host(ip),
        port=port,
        host_header=host_header,
        server_name=host,
    )


@final
class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    _server_hostname: str
    _tls_context: ssl.SSLContext | None

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        server_hostname: str,
        context: ssl.SSLContext | None = None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._server_hostname = server_hostname
        self._tls_context = context

    @override
    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)
        context = self._tls_context or ssl.create_default_context()
        sock = self.sock
        if sock is None:
            raise OSError("HTTP connection produced no socket")
        self.sock = context.wrap_socket(sock, server_hostname=self._server_hostname)


@final
class SafeOpenHandler(BaseHandler):
    """Per-request DNS pin: TCP to the checked IP, SNI/Host/geturl keep the hostname."""

    allow_private: bool
    _tls_context: ssl.SSLContext | None
    guard: Callable[[str], str] | None

    def __init__(
        self,
        *,
        allow_private: bool,
        context: ssl.SSLContext | None = None,
        guard: Callable[[str], str] | None = None,
    ) -> None:
        self.allow_private = allow_private
        self._tls_context = context
        self.guard = guard

    def http_open(self, req: Request) -> http.client.HTTPResponse:
        return self._pinned_open(req, tls=False)

    def https_open(self, req: Request) -> http.client.HTTPResponse:
        return self._pinned_open(req, tls=True)

    def _pinned_open(self, req: Request, *, tls: bool) -> http.client.HTTPResponse:
        raw = req.get_full_url()
        guard = self.guard
        if callable(guard):
            _ = guard(raw)
        safe = prepare_safe_request(raw, allow_private=self.allow_private)
        req.add_unredirected_header("Host", safe.host_header)
        req.headers["Host"] = safe.host_header

        def http_class(_host: str, **kwargs: object) -> http.client.HTTPConnection:
            timeout = kwargs.get("timeout")
            timeout_f = float(timeout) if isinstance(timeout, (int, float)) else None
            if tls:
                return _PinnedHTTPSConnection(
                    safe.connect_host,
                    safe.port,
                    server_hostname=safe.server_name,
                    context=self._tls_context,
                    timeout=timeout_f,
                )
            return http.client.HTTPConnection(safe.connect_host, safe.port, timeout=timeout_f)

        if tls:
            return HTTPSHandler(context=self._tls_context).do_open(http_class, req)
        return HTTPHandler().do_open(http_class, req)


def safe_opener(
    *,
    allow_private: bool,
    context: ssl.SSLContext | None = None,
    extra_handlers: tuple[BaseHandler, ...] = (),
    guard: Callable[[str], str] | None = None,
) -> OpenerDirector:
    handlers: list[BaseHandler] = [
        ProxyHandler({}),
        *extra_handlers,
        SafeOpenHandler(allow_private=allow_private, context=context, guard=guard),
    ]
    return build_opener(*handlers)
