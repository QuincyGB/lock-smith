"""The audit battery against mocked targets (httpx MockTransport).

Each fixture target isolates one behaviour: a healthy paywalled route,
an open route (200 unpaid), a route that accepts forged payments, a
route whose errors leak internals, a route serving its .env, a route
whose discovery disagrees with its challenge, and a route that is down.
DNS is stubbed by conftest; no network is touched.
"""

import asyncio
import json

import httpx
import pytest

from app.audit import AuditUnavailable, CheckResult, compose_verdict, run_audit

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
OWNER = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"
TARGET = "https://target.example.com/v1/thing"
ORIGIN = "https://target.example.com"

CHALLENGE = {
    "x402Version": 2,
    "resource": {"url": TARGET, "description": "a paid thing", "mimeType": "application/json"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": USDC,
            "amount": "20000",
            "payTo": OWNER,
            "maxTimeoutSeconds": 300,
        }
    ],
    "extensions": {},
}

MANIFEST = {
    "x402Version": 2,
    "service": "target",
    "resources": [
        {
            "resource": TARGET,
            "method": "POST",
            "accepts": CHALLENGE["accepts"],
        }
    ],
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _audit(handler, url=TARGET):
    return asyncio.run(run_audit(url, client=_client(handler)))


def _by_id(result):
    return {c["id"]: c for c in result["checks"]}


def healthy_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/x402":
        return httpx.Response(200, json=MANIFEST)
    if path != "/v1/thing":
        return httpx.Response(404, json={"error": "not found"})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(413, json={"error": "too large"})
    # Paywall-first service: everything unpaid draws the challenge,
    # including malformed bodies and payment-shaped headers.
    return httpx.Response(402, json=CHALLENGE)


def test_healthy_target_is_secure():
    result = _audit(healthy_handler)
    assert result["verdict"] == "SECURE"
    assert result["summary"] == {"passed": 8, "findings": 0, "not_tested": 0, "worst_severity": None}
    assert result["probes_used"] <= 20
    assert result["terms_observed"]["amount_units"] == "20000"
    assert result["terms_observed"]["pay_to"] == OWNER
    assert set(_by_id(result)) == {
        "paywall_present", "challenge_sanity", "garbage_payment", "forged_payment",
        "exposure_surface", "error_hygiene", "body_cap", "discovery_consistency",
    }


def open_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/.well-known/x402":
        return httpx.Response(404, text="nope")
    return httpx.Response(200, json={"data": "free for everyone"})


def test_open_target_is_exposed():
    result = _audit(open_handler)
    checks = _by_id(result)
    assert result["verdict"] == "EXPOSED"
    assert checks["paywall_present"]["status"] == "finding"
    assert checks["paywall_present"]["severity"] == "critical"
    assert checks["garbage_payment"]["status"] == "finding"
    assert checks["garbage_payment"]["severity"] == "critical"
    # No challenge exists, so challenge-dependent checks must not guess.
    assert checks["challenge_sanity"]["status"] == "not_tested"
    assert checks["forged_payment"]["status"] == "not_tested"
    assert "fix" in checks["paywall_present"]


def forged_accepting_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/x402":
        return httpx.Response(200, json=MANIFEST)
    if path != "/v1/thing":
        return httpx.Response(404, json={})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(413, json={})
    sig = request.headers.get("payment-signature", "")
    # Waves through any long, payload-shaped payment header; junk is
    # short, so the garbage check still sees a (correct) 402.
    if len(sig) > 200:
        return httpx.Response(200, json={"data": "paid content"})
    return httpx.Response(402, json=CHALLENGE)


def test_forged_payment_acceptance_is_critical():
    result = _audit(forged_accepting_handler)
    checks = _by_id(result)
    assert checks["garbage_payment"]["status"] == "pass"
    assert checks["forged_payment"]["status"] == "finding"
    assert checks["forged_payment"]["severity"] == "critical"
    assert result["verdict"] == "EXPOSED"


def leaky_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/x402":
        return httpx.Response(200, json=MANIFEST)
    if path != "/v1/thing":
        return httpx.Response(404, json={})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(413, json={})
    if body.startswith(b"{not json"):
        return httpx.Response(
            500,
            text='Traceback (most recent call last):\n  File "/srv/app/main.py", line 42, in thing\nValueError: boom',
        )
    return httpx.Response(402, json=CHALLENGE)


def test_error_leak_is_a_finding():
    result = _audit(leaky_handler)
    checks = _by_id(result)
    assert checks["error_hygiene"]["status"] == "finding"
    assert checks["error_hygiene"]["severity"] == "medium"
    assert result["verdict"] == "FINDINGS"


def env_exposed_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.env":
        return httpx.Response(200, text="DATABASE_URL=postgres://x\nAPI_SECRET_KEY=hunter2\n")
    if path == "/.well-known/x402":
        return httpx.Response(200, json=MANIFEST)
    if path != "/v1/thing":
        return httpx.Response(404, json={})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(413, json={})
    return httpx.Response(402, json=CHALLENGE)


def test_env_exposure_is_a_finding():
    result = _audit(env_exposed_handler)
    checks = _by_id(result)
    assert checks["exposure_surface"]["status"] == "finding"
    assert ".env" in checks["exposure_surface"]["detail"]
    assert result["verdict"] in ("FINDINGS", "EXPOSED")


def mismatched_discovery_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/x402":
        bad = json.loads(json.dumps(MANIFEST))
        bad["resources"][0]["accepts"][0]["amount"] = "999999"  # advertises $1.00, charges $0.02
        return httpx.Response(200, json=bad)
    if path != "/v1/thing":
        return httpx.Response(404, json={})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(413, json={})
    return httpx.Response(402, json=CHALLENGE)


def test_discovery_mismatch_is_a_finding():
    result = _audit(mismatched_discovery_handler)
    checks = _by_id(result)
    assert checks["discovery_consistency"]["status"] == "finding"
    assert result["verdict"] == "FINDINGS"


def no_body_cap_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/x402":
        return httpx.Response(200, json=MANIFEST)
    if path != "/v1/thing":
        return httpx.Response(404, json={})
    body = request.content or b""
    if len(body) > 1024 * 1024:
        return httpx.Response(200, json={"data": "swallowed it"})  # no cap at all
    return httpx.Response(402, json=CHALLENGE)


def test_missing_body_cap_is_a_finding():
    result = _audit(no_body_cap_handler)
    checks = _by_id(result)
    assert checks["body_cap"]["status"] == "finding"
    assert checks["body_cap"]["severity"] == "high"


def down_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def test_unreachable_target_raises_unavailable():
    with pytest.raises(AuditUnavailable):
        _audit(down_handler)


def test_compose_verdict_thresholds():
    ok = CheckResult("a", "A", "pass", detail="fine")
    low = CheckResult("b", "B", "finding", severity="low", detail="x", fix="y")
    high = CheckResult("c", "C", "finding", severity="high", detail="x", fix="y")
    crit = CheckResult("d", "D", "finding", severity="critical", detail="x", fix="y")
    nt = CheckResult("e", "E", "not_tested", detail="n/a")
    assert compose_verdict([ok, nt]) == "SECURE"
    assert compose_verdict([ok, low]) == "FINDINGS"
    assert compose_verdict([ok, high]) == "EXPOSED"
    assert compose_verdict([ok, crit]) == "EXPOSED"
