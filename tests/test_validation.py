"""Input validation: non-URLs and non-public targets are refused as
ValueError (the route answers 422, which never settles), and a refused
target is never fetched."""

import asyncio

import httpx
import pytest

from app.audit import run_audit
from app.probe import ssrf_check


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "https://",
        "",
    ],
)
def test_non_urls_are_refused(url):
    with pytest.raises(ValueError):
        asyncio.run(run_audit(url))


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://127.0.0.1:8080/v1/thing",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/v1/thing",
        "http://192.168.1.1/v1/thing",
        "http://[::1]/v1/thing",
    ],
)
def test_non_public_targets_are_refused(url):
    with pytest.raises(ValueError):
        ssrf_check(url)
    with pytest.raises(ValueError):
        asyncio.run(run_audit(url))


def test_refused_target_is_never_fetched():
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(str(request.url))
        return httpx.Response(402, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        asyncio.run(run_audit("http://127.0.0.1:8080/v1/thing", client=client))
    assert called == []
