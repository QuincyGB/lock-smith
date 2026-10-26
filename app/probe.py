"""Probe transport — LockSmith's only way of touching a target.

Every fetch follows the fleet SSRF discipline (ListSmith/StallRow,
security audit 2026-10-25): only http(s), the host must resolve
exclusively to public addresses, every redirect hop is re-checked
BEFORE it is fetched, and response bodies are read under a hard cap.
LockSmith NEVER attaches a payment header to a target request, so a
target can never charge us — the audit is unpaid by construction.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx

USER_AGENT = "lock-smith/1.0 (x402 endpoint security audit)"

_MAX_PROBE_BYTES = 512 * 1024  # a 402 challenge / error page is a few KB
_MAX_REDIRECTS = 5


def ssrf_check(url: str) -> None:
    """Reject non-http(s) URLs and any host resolving to a private,
    loopback, link-local, reserved, or multicast address."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"host does not resolve: {host}") from e
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(f"URL host resolves to a non-public address ({ip})")


class ProbeRefused(Exception):
    """The probe refused the target (SSRF guard, redirect overflow, or
    an oversized body). Surfaced as a probe error, never a fetch."""


async def _read_capped(resp: httpx.Response, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        total += len(chunk)
        if total > cap:
            raise ProbeRefused(f"target body exceeds the {cap}-byte probe cap")
        chunks.append(chunk)
    return b"".join(chunks)


async def fetch(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
    timeout: float,
    content: bytes | None = None,
    cap: int = _MAX_PROBE_BYTES,
) -> tuple[int, httpx.Headers, bytes]:
    """One probe request with manual redirect following — every hop is
    SSRF-checked before it is fetched."""
    current = url
    method_now, content_now = method, content
    for hop in range(_MAX_REDIRECTS + 1):
        await asyncio.to_thread(ssrf_check, current)  # blocking DNS — off the loop
        async with client.stream(
            method_now,
            current,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            content=content_now,
        ) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return resp.status_code, resp.headers, b""
                if hop == _MAX_REDIRECTS:
                    raise ProbeRefused("target redirected too many times")
                current = urljoin(current, location)
                if resp.status_code == 303:
                    method_now = "GET"
                    content_now = None
                continue
            return resp.status_code, resp.headers, await _read_capped(resp, cap)
    raise ProbeRefused("target redirected too many times")  # pragma: no cover


async def fetch_origin_text(
    client: httpx.AsyncClient,
    origin: str,
    path: str,
    timeout: float,
) -> tuple[int | None, str]:
    """GET origin+path for the exposure check; returns (status, small
    text snippet). Probe-halting failures return (None, reason) so the
    caller can mark the item not-tested instead of guessing."""
    try:
        status, _headers, body = await fetch(
            client,
            "GET",
            origin + path,
            {"user-agent": USER_AGENT, "accept": "text/plain, */*"},
            timeout,
            cap=64 * 1024,
        )
    except ProbeRefused as e:
        return None, f"probe refused: {e}"
    except ValueError as e:  # SSRF guard refusal
        return None, f"probe refused: {e}"
    except httpx.HTTPError as e:
        return None, f"request failed: {e}"
    return status, body.decode("utf-8", errors="replace")[:4096]


async def send_large_body(
    client: httpx.AsyncClient,
    url: str,
    body: bytes,
    timeout: float,
) -> dict:
    """The body-cap sanity probe: ONE POST with an oversized junk body.

    Reads at most a few KB of any response and never drains the socket.
    Returns {status, refused_early, error}: refused_early is True when
    the target closed/reset the connection while we were still sending
    (a healthy refusal shape); it is NOT counted as a pass for 200s —
    the caller judges.
    """
    await asyncio.to_thread(ssrf_check, url)
    request = client.build_request(
        "POST",
        url,
        headers={
            "user-agent": USER_AGENT,
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
        content=body,
        timeout=timeout,
    )
    try:
        resp = await client.send(request, stream=True, follow_redirects=False)
    except httpx.HTTPError as e:
        name = type(e).__name__
        # A reset/refusal mid-send means the target pushed back on the
        # oversized body instead of swallowing it.
        if name in ("RemoteProtocolError", "ConnectError", "WriteError", "ReadError"):
            return {"status": None, "refused_early": True, "error": name}
        return {"status": None, "refused_early": False, "error": name}
    status = resp.status_code
    try:
        read = 0
        async for chunk in resp.aiter_bytes():  # read a token amount only
            read += len(chunk)
            if read > 8192:
                break
    except httpx.HTTPError:
        pass
    finally:
        await resp.aclose()
    return {"status": status, "refused_early": False, "error": None}


_shared: httpx.AsyncClient | None = None


def shared_client() -> httpx.AsyncClient:
    """One process-wide client for target probes (connection reuse
    across audits). Callers must NOT close it."""
    global _shared
    if _shared is None or _shared.is_closed:
        _shared = httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=90.0,
            ),
        )
    return _shared
