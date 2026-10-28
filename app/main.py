"""LockSmith — x402 endpoint security audits for x402 services.

Paid:   POST /v1/audit   (eight automated security checks, USDC via x402 v2 on Base)
Free:   GET  /, /health, /quote, /.well-known/x402, /skill.md, /llms.txt
        POST /v1/nudge (fleet-health nudge inbox — signed mail, not
        a product) and POST /v1/internal/nudges (owner read, gated
        by the fleet internal secret like /v1/internal/audit)

The audit is observation-only toward the target: LockSmith probes it
WITHOUT paying it, using non-destructive unpaid requests. Automated
security checks — not a penetration test.
"""

from __future__ import annotations

import hmac
import json
import logging
import os

# Some shells/hosts export a no_proxy list containing bracketed IPv6
# entries ("[::1]"). The x402 SDK's httpx-based facilitator client parses
# that list as URLs and dies with "Invalid port: ':1]'", which turns every
# unpaid call into a 500 instead of a 402. Scrub just the bracketed
# entries before any SDK client is constructed. (Fleet-wide fix,
# carried over from RouteVerdict/ListSmith.)
for _var in ("no_proxy", "NO_PROXY"):
    _val = os.environ.get(_var)
    if _val:
        _kept = [e for e in _val.split(",") if "[" not in e and "]" not in e]
        os.environ[_var] = ",".join(_kept)

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption, RouteConfig
from x402.http.middleware import fastapi_payment_middleware
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.server import x402ResourceServer

from . import nudge as nudge_svc
from .audit import AuditUnavailable, run_audit
from .config import load_settings
from .nudge import NudgeStore, resolve_nudge_path
from .probe import USER_AGENT, fetch as _probe_fetch, shared_client
from .discovery import (
    OWNERSHIP_PROOFS,
    audit_extension,
    llms_txt,
    skill_md,
    x402_manifest,
)

log = logging.getLogger("lock-smith")
logging.basicConfig(level=logging.INFO)

settings = load_settings()  # raises if payout wallet is a placeholder

# Fleet-health nudge inbox store (app/nudge.py): signed inbound mail
# in a small sqlite file; path resolution is LOCKSMITH_NUDGE_PATH,
# else a mounted /data volume, else a local file.
_nudge_store = NudgeStore(resolve_nudge_path())

# --- x402 wiring -------------------------------------------------------------
# The facilitator is chosen by X402_FACILITATOR_URL alone (plus CDP keys for
# the CDP branch). Cataloging is settlement-driven per facilitator — each
# index lists only settlements through its OWN facilitator:
#   * CDP (api.cdp.coinbase.com, needs CDP_API_KEY_ID/SECRET): CDP Bazaar.
#   * PayAI (facilitator.payai.network, no key for exact): PayAI index.
#   * default keyless ultravioletadao: settles Base, feeds no major index.
# One deployment settles through one facilitator at a time; to appear in
# both indexes, settle at least one call under each configuration.
if settings.use_cdp:
    from .cdp_auth import cdp_facilitator_config

    assert settings.cdp_api_key_id and settings.cdp_api_key_secret
    facilitator = HTTPFacilitatorClient(
        cdp_facilitator_config(settings.cdp_api_key_id, settings.cdp_api_key_secret)
    )
    log.info("facilitator: CDP (Bazaar cataloging path)")
elif settings.use_payai:
    facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=settings.facilitator_url))
    log.info("facilitator: PayAI (PayAI index cataloging path)")
else:
    facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=settings.facilitator_url))
    log.info("facilitator: %s (%s)", settings.facilitator_url, settings.network)

resource_server = x402ResourceServer(facilitator)
resource_server.register(settings.network, ExactEvmScheme())

AUDIT_DESCRIPTION = (
    "Automated security checks for one x402 endpoint — not a penetration "
    "test. Eight non-destructive, unpaid probes: paywall presence, challenge "
    "sanity, garbage and forged (invalid-signature) payment rejection, "
    "exposure surface, error hygiene, body-size cap, discovery consistency. "
    "Returns SECURE / FINDINGS / EXPOSED with a fix note per finding. Use "
    "this when you operate an x402 route and want its locks checked the "
    "way an attacker would rattle them."
)

_TAGS = ["x402", "security", "audit", "agents"]

routes = {
    "POST /v1/audit": RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                pay_to=settings.pay_to,
                price=settings.audit_price_usdc,
                network=settings.network,
            )
        ],
        description=AUDIT_DESCRIPTION,
        mime_type="application/json",
        service_name=settings.service_name,  # ≤32 chars, forwarded to Bazaar
        tags=_TAGS,
        extensions={"bazaar": audit_extension()},
    ),
}

# --- app ---------------------------------------------------------------------
app = FastAPI(title="lock-smith", version="1.0.0")

# Public contact for the OpenAPI info block. x402scan / tryponcho read
# info.contact.email for merchant pages and owner contact; the owner
# approved publishing this address in the discovery documents
# (2026-10-26).
CONTACT = {"name": "Verdict Row", "email": "quincyga.brown@gmail.com"}


def _openapi_with_ownership_proofs():
    """Default OpenAPI document plus the x402scan ownership-proof root
    keys (x-discovery / x-agentcash-provenance). x402scan reads these to
    verify control of the payTo address — see OWNERSHIP_PROOFS in
    discovery.py; removing them un-verifies the listing."""
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title, version=app.version, routes=app.routes, contact=CONTACT
    )
    schema["x-discovery"] = {"ownershipProofs": OWNERSHIP_PROOFS}
    schema["x-agentcash-provenance"] = {"ownershipProofs": OWNERSHIP_PROOFS}
    app.openapi_schema = schema
    return schema


app.openapi = _openapi_with_ownership_proofs

# Build the payment middleware ONCE. Constructing it runs the SDK's
# initialize(), which synchronously fetches the facilitator's /supported
# document over the network — building it per request added a full
# external round-trip, on the event loop, to EVERY request including
# /health and the unpaid 402 challenges (the fleet's 2026-10-24
# latency-variance problem). Same fix as the rest of the fleet.
_payment_middleware = fastapi_payment_middleware(routes, resource_server)


_PASS_PATHS = {"/v1/audit"}


@app.middleware("http")
async def x402_middleware(request: Request, call_next):
    # A call presenting a Fleet Pass id is paid from the pass ledger
    # in StallRow: debit before the handler, refund on failure.
    from . import fleet_pass as _fleet_pass

    debit = await _fleet_pass.debit_for(request, settings.service_name, _PASS_PATHS)
    if isinstance(debit, JSONResponse):
        return debit
    if debit:
        response = await call_next(request)
        if response.status_code >= 400:
            await _fleet_pass.refund(debit)
        return response
    return await _payment_middleware(request, call_next)


# Request-body cap (fleet security standard, audit 2026-10-25): every
# legitimate body in this API is a small JSON document; an uncapped body
# lets a caller stream unbounded bytes at the parser. Chunked bodies
# without a Content-Length are the residual gap (terminated at the edge).
_MAX_BODY_BYTES = 1024 * 1024


@app.middleware("http")
async def _body_cap(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is not None and length.isdigit() and int(length) > _MAX_BODY_BYTES:
        return JSONResponse({"error": "request body too large"}, status_code=413)
    return await call_next(request)


class AuditRequest(BaseModel):
    endpoint_url: str = Field(description="Full URL of the x402 endpoint (paid route) to audit")
    mode: str = Field(
        default="full",
        pattern="^(full|compact)$",
        description=(
            "Response mode. 'full' (default) returns every check's full "
            "detail prose. 'compact' returns the same audit — same "
            "checks, statuses, terms and summary — with headline "
            "summaries for passing checks and the short scope note, for "
            "buyers who republish or forward the response (listing "
            "samples over ~1.5 KB get dropped by some indexers). "
            "Findings and not_tested checks keep full detail in both "
            "modes."
        ),
    )


def _public_base(request: Request) -> str:
    """Public base URL of this service. Railway terminates TLS at the edge,
    so the request scheme arrives as http — indexers and agents need https."""
    base = str(request.base_url).rstrip("/")
    if base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LockSmith — security audits for x402 endpoints</title>
<meta name="description" content="Automated security checks for x402 endpoints — not a penetration test. Eight non-destructive, unpaid probes check the paywall, payment rejection, exposure surface, error hygiene, body caps, and discovery consistency. $0.50 per endpoint.">
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         max-width: 760px; margin: 40px auto; padding: 0 20px 60px;
         line-height: 1.55; color: #16202a; background: #fbfcfd; }
  h1 { font-size: 2rem; margin-bottom: .2em; }
  .tag { font-size: 1.1rem; color: #33475b; margin-top: 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  pre { background: #0f1b26; color: #dcebf5; padding: 14px 16px;
        border-radius: 8px; overflow-x: auto; font-size: .85rem; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  td, th { border-bottom: 1px solid #dde5ec; padding: 6px 8px;
           text-align: left; vertical-align: top; }
  .pill { display: inline-block; background: #e7f0e9; color: #1d5c33;
          border-radius: 999px; padding: 2px 10px; font-size: .85rem; }
  a { color: #0b5cad; }
  .limits { background: #fdf6e5; border: 1px solid #ecd9a0;
            border-radius: 8px; padding: 10px 14px; }
</style>
</head>
<body>
<h1>LockSmith</h1>
<p class="tag">The lock-checker for the x402 Bazaar. Your route's listing
can be perfect and its locks still broken: a paywall that answers unpaid,
a payment gate that waves junk through, a <code>.env</code> file sitting
on the public origin. LockSmith rattles the locks the way an attacker
would — with eight automated, non-destructive, unpaid probes — and hands
back a verdict with a fix note for every finding. <strong>Automated
security checks, not a penetration test.</strong> No accounts, no API
keys: <em>payment is the authentication.</em></p>

<p><span class="pill">Live on Base mainnet</span>
<span class="pill">x402 v2 · exact scheme</span>
<span class="pill">Audit $0.50 per endpoint</span>
<span class="pill">Unpaid probes only — never pays the target</span></p>

<h2>The eight checks</h2>
<table>
  <tr><th>#</th><th>Check</th><th>What it does</th></tr>
  <tr><td>1</td><td>Paywall present</td><td>An unpaid request must draw HTTP 402 with a parseable x402 challenge. A 200 unpaid is EXPOSED.</td></tr>
  <tr><td>2</td><td>Challenge sanity</td><td>The challenge's scheme, network, asset, amount, and payTo must be complete and self-consistent.</td></tr>
  <tr><td>3</td><td>Garbage payment rejected</td><td>Base64-junk payment headers must draw a 402, not content.</td></tr>
  <tr><td>4</td><td>Forged payment rejected</td><td>A structurally valid EIP-3009 authorization with an invalid signature must be rejected.</td></tr>
  <tr><td>5</td><td>Exposure surface</td><td><code>/.env</code>, <code>/.git/config</code>, <code>/debug</code>, <code>/metrics</code>, <code>/admin</code> must not serve real content.</td></tr>
  <tr><td>6</td><td>Error hygiene</td><td>Malformed input must draw clean errors — no stack traces, file paths, SQL, or debug pages.</td></tr>
  <tr><td>7</td><td>Body-cap sanity</td><td>One ~1.1 MiB junk body must be refused, not swallowed or crashed on.</td></tr>
  <tr><td>8</td><td>Discovery consistency</td><td>Published discovery must advertise the route with terms matching the live challenge.</td></tr>
</table>

<h2>How to call it</h2>
<pre>curl -X POST https://lock-smith-production.up.railway.app/v1/audit \\
  -H 'content-type: application/json' \\
  -d '{"endpoint_url":"https://your-service.example.com/v1/route"}'</pre>
<p>Unpaid calls return an HTTP 402 x402 challenge. Pay with any x402 v2
client, retry with the payment header, and the audit comes back. The
target endpoint is probed unpaid and is never charged.</p>

<h2>Endpoints</h2>
<table>
  <tr><th>Route</th><th>Price</th><th>Purpose</th></tr>
  <tr><td><code>POST /v1/audit</code></td><td>$0.50</td><td>Security-audit one x402 endpoint (paid, x402)</td></tr>
  <tr><td><code>GET /quote</code></td><td>free</td><td>Prices, asset, network, pay-to wallet</td></tr>
  <tr><td><code>GET /.well-known/x402</code></td><td>free</td><td>Machine-readable service manifest</td></tr>
  <tr><td><code>GET /skill.md</code></td><td>free</td><td>Documentation written for agents</td></tr>
  <tr><td><code>GET /llms.txt</code></td><td>free</td><td>Compact agent index</td></tr>
  <tr><td><code>GET /health</code></td><td>free</td><td>Liveness</td></tr>
</table>
<p>Source code:
<a href="https://github.com/QuincyGB/lock-smith">github.com/QuincyGB/lock-smith</a>
(public source — the audit battery is deterministic and fully
inspectable, and the test suite ships with it). Sibling services:
<a href="https://github.com/QuincyGB/list-smith">ListSmith</a> (grades
the listing — the shop window) and
<a href="https://github.com/QuincyGB/stall-row">StallRow</a> (the
utility stall row).</p>

<div class="limits">
<strong>Honest limits:</strong> these are automated security checks,
not a penetration test. LockSmith only ever sends unpaid,
non-destructive probes — it cannot judge anything that requires a real
payment to the target, your authorization logic behind the paywall, or
your business logic. A check that could not run is reported as
not_tested, never as a pass. Auditing a non-public address is refused.
</div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def landing():
    return LANDING_HTML


@app.get("/health")
async def health():
    return {"ok": True, "service": settings.service_name}


@app.get("/quote")
async def quote():
    """Free: what the paid endpoint costs and where it settles."""
    return {
        "service": settings.service_name,
        "endpoints": {
            "/v1/audit": {"price": settings.audit_price_usdc, "purpose": "security audit of one x402 endpoint"},
        },
        "asset": "USDC",
        "network": settings.network,
        "payTo": settings.pay_to,
        "protocol": "x402 v2 (exact scheme)",
    }


@app.get("/.well-known/x402")
async def well_known(request: Request):
    return JSONResponse(x402_manifest(settings, _public_base(request)))


@app.get("/skill.md", response_class=PlainTextResponse)
async def skill(request: Request):
    return skill_md(settings, _public_base(request))


@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms(request: Request):
    return llms_txt(settings, _public_base(request))


@app.post("/v1/internal/audit")
async def audit_internal(req: AuditRequest, request: Request):
    """Fleet-internal unpaid path for StallRow's /v1/orchestrate.
    Secret discipline mirrors Token Verdict's RapidAPI route:
    FLEET_INTERNAL_SECRET unset = 404, wrong secret = 403. Absent
    from the x402 routes dict and every discovery surface."""
    secret = settings.fleet_internal_secret
    if not secret:
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    presented = request.headers.get("x-fleet-internal-secret", "")
    if not hmac.compare_digest(presented, secret):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return await audit(req)


# --- Nudge inbox ------------------------------------------------------------------
# The two-way leg of Fleet Check (app/nudge.py; spec:
# x402-loop-kits/nudge-inbox.md). POST /v1/nudge is FREE — inbound
# mail is not a product, and it is absent from the x402 `routes`
# dict and every priced surface, so the priced route count does
# not move. Every message is EIP-191-signed; unsigned or
# wrongly-signed mail is a clean 4xx, never a 5xx. The owner reads
# the inbox through the fleet-internal gate, same discipline as
# /v1/internal/audit: secret unset = 404, wrong secret = 403.

class NudgeInboxReadRequest(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)


async def _stall_pay_to(stall: str) -> str | None:
    """The payTo a stall's own discovery doc publishes — the
    opt-out verifier's ground truth for who controls that stall.
    Fetched under this service's probe discipline (app/probe.py):
    SSRF-checked, redirect hops re-checked, body read capped."""
    try:
        status, _headers, body = await _probe_fetch(
            shared_client(),
            "GET",
            f"{stall.rstrip('/')}/.well-known/x402",
            {"user-agent": USER_AGENT, "accept": "application/json"},
            settings.fetch_timeout_s,
        )
    except Exception:  # noqa: BLE001 — an unreadable doc proves nothing
        return None
    if status != 200 or not body:
        return None
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    pay_to = doc.get("payTo") if isinstance(doc, dict) else None
    return pay_to if isinstance(pay_to, str) else None


@app.post("/v1/nudge")
async def nudge_inbox(request: Request):
    """Receive one fleet-health nudge (or opt-out). The message is
    validated structurally, then its signature must recover to the
    claimed sender wallet, then — for nudges — the per-sender rate
    limit applies. Verified nudges are stored deduped; opt-outs
    must be signed by the payTo the named stall's own discovery
    doc publishes, and are recorded for the sender engine."""
    try:
        raw = await request.body()
        message = json.loads(raw) if raw else None
    except ValueError:
        return JSONResponse(
            {"error": "body must be a JSON object"}, status_code=400
        )
    try:
        nudge_svc.validate_message(message)
        nudge_svc.verify_sender(message)
    except nudge_svc.NudgeError as e:
        return JSONResponse({"error": str(e)}, status_code=e.http_status)
    if message["kind"] == nudge_svc.KIND_OPT_OUT:
        pay_to = await _stall_pay_to(message["stall"])
        if pay_to is None:
            return JSONResponse(
                {
                    "error": "could not read the stall's discovery "
                    "doc to verify payTo control"
                },
                status_code=422,
            )
        if pay_to.lower() != message["sender"].lower():
            return JSONResponse(
                {
                    "error": "opt-out must be signed by the stall's "
                    "published payTo wallet"
                },
                status_code=403,
            )
        _nudge_store.record_optout(message["stall"], message["sender"])
        return {
            "ok": True,
            "kind": message["kind"],
            "opted_out": message["stall"].rstrip("/"),
        }
    if not nudge_svc.RATE_LIMITER.allow(
        message["sender"], nudge_svc.rate_limit_per_hour()
    ):
        return JSONResponse(
            {"error": "rate limit: too many nudges from this sender"},
            status_code=429,
        )
    stored = _nudge_store.store_nudge(message, nudge_svc.dedupe_key(message))
    return {
        "ok": True,
        "kind": message["kind"],
        "stored": stored,
        "duplicate": not stored,
    }


@app.post("/v1/internal/nudges")
async def nudge_inbox_read(
    req: NudgeInboxReadRequest | None = None, request: Request = None
):
    """Owner read of the nudge inbox: stored nudges (newest first)
    plus the opt-out registry. Fleet-internal secret gate, mirroring
    /v1/internal/audit exactly."""
    secret = settings.fleet_internal_secret
    if not secret:
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    presented = request.headers.get("x-fleet-internal-secret", "")
    if not hmac.compare_digest(presented, secret):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    limit = req.limit if req is not None else 50
    return {
        "count": _nudge_store.nudge_count(),
        "nudges": _nudge_store.list_nudges(limit),
        "optouts": _nudge_store.list_optouts(),
    }


@app.post("/v1/audit")
async def audit(req: AuditRequest):
    """Paid endpoint — unreachable until the x402 middleware verifies payment."""
    endpoint_url = req.endpoint_url.strip()
    try:
        return await run_audit(endpoint_url, timeout=settings.fetch_timeout_s, mode=req.mode)
    except ValueError as e:
        # Invalid input (bad URL / non-public target). 422 never settles.
        return JSONResponse({"error": str(e)}, status_code=422)
    except AuditUnavailable as e:
        # Target unreachable / probe failure. 502 never settles.
        return JSONResponse({"error": f"audit unavailable: {e}"}, status_code=502)
    except Exception:  # noqa: BLE001 — never leak tracebacks to callers
        log.exception("audit failed for %s", endpoint_url)
        return JSONResponse({"error": "audit failed"}, status_code=502)


def main() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=False)


if __name__ == "__main__":
    main()
