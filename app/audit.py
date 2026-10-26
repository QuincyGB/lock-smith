"""LockSmith audit battery — eight non-destructive, unpaid checks.

The battery (exactly these, as advertised in the discovery document):

 1. paywall_present        unpaid request must draw a 402 x402 challenge
 2. challenge_sanity       the challenge's terms must be well-formed
 3. garbage_payment        base64-junk payment header must be rejected
 4. forged_payment         invalid-signature EIP-3009 auth must be rejected
 5. exposure_surface       /.env, /.git/config, /debug, /metrics, /admin
 6. error_hygiene          error bodies must not leak traces/paths/SQL
 7. body_cap               one ~1.1 MiB POST must be refused, not swallowed
 8. discovery_consistency  published discovery must match the live terms

Honesty rules: a check that could not run is "not_tested" with a
reason, never a pass. A target that cannot be reached at all raises
AuditUnavailable (the route answers 502 and the caller's payment does
not settle). Invalid input (non-URL, non-public host) raises ValueError
(the route answers 422, which likewise never settles).

Probe budget: at most ~20 requests per audit, hard-capped below.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from .parsers import KNOWN_ASSET_DECIMALS, format_price, parse_challenge
from .probe import (
    USER_AGENT,
    ProbeRefused,
    fetch,
    fetch_origin_text,
    send_large_body,
    shared_client,
    ssrf_check,
)

AUDIT_VERSION = "1.0"
MAX_PROBES = 20

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# EIP-712 domain for USDC's EIP-3009 TransferWithAuthorization on a given
# chain, keyed by the chain id in the challenge's CAIP-2 network string.
# Only chains we can name the verifying contract for are forge-testable;
# anything else is honestly not_tested.
_EIP712_DOMAINS = {
    8453: {"name": "USD Coin", "version": "2", "chainId": 8453,
           "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
}

_TRANSFER_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

_LEAK_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "python stack trace"),
    (re.compile(r"\bFile \"[^\"]+\.py\", line \d+"), "source file path with line number"),
    (re.compile(r"\b(ORA-\d{5}|SQLSTATE|syntax error at or near|mysql_fetch|pg_query)\b", re.I), "database error detail"),
    (re.compile(r"\b(werkzeug|debugger|flask\.app)\b", re.I), "framework debug page marker"),
    (re.compile(r"/(?:srv|app|home|usr/lib/python|var/task)/[^\s\"']*"), "server filesystem path"),
    (re.compile(r"at [A-Za-z_$][\w$.]*\([^)]*:\d+:\d+\)"), "javascript stack frame"),
]


class AuditUnavailable(Exception):
    """The target could not be reached / our probe path failed.
    The route maps this to 502 — the caller's payment never settles."""


@dataclass
class CheckResult:
    id: str
    name: str
    status: str  # "pass" | "finding" | "not_tested"
    severity: str | None = None  # set only when status == "finding"
    detail: str = ""
    fix: str | None = None  # set only when status == "finding"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }
        if self.severity is not None:
            out["severity"] = self.severity
        if self.fix is not None:
            out["fix"] = self.fix
        return out


@dataclass
class _Ctx:
    target_url: str
    origin: str
    timeout: float
    client: httpx.AsyncClient
    probes_used: int = 0
    probe: dict | None = None  # primary unpaid probe result
    challenge: Any = None  # parsed ChallengeParse
    primary: Any = None  # primary Accept

    def budget(self, n: int = 1) -> bool:
        if self.probes_used + n > MAX_PROBES:
            return False
        self.probes_used += n
        return True


async def _primary_probe(ctx: _Ctx) -> dict:
    """GET the target; if that doesn't draw the 402, POST {} — the
    ListSmith shape. Raises AuditUnavailable when nothing answers."""
    headers = {"user-agent": USER_AGENT}
    chosen = None
    error: str | None = None
    try:
        if not ctx.budget():
            raise AuditUnavailable("probe budget exhausted before the primary probe")
        status, resp_headers, body = await fetch(ctx.client, "GET", ctx.target_url, headers, ctx.timeout)
        chosen = (status, resp_headers, body)
        if status != 402:
            if not ctx.budget():
                raise AuditUnavailable("probe budget exhausted before the primary probe")
            status2, headers2, body2 = await fetch(
                ctx.client, "POST", ctx.target_url,
                {**headers, "content-type": "application/json"},
                ctx.timeout, content=b"{}",
            )
            if status2 == 402:
                chosen = (status2, headers2, body2)
    except (ProbeRefused, ValueError) as e:
        error = f"probe refused: {e}"
    except httpx.HTTPError as e:
        error = str(e)
    if chosen is None:
        raise AuditUnavailable(f"target unreachable: {error or 'no response'}")
    return {
        "status": chosen[0],
        "headers": dict(chosen[1]),
        "body": chosen[2],
        "error": error,
    }


# --- the eight checks ---------------------------------------------------------


def _check_paywall(ctx: _Ctx) -> CheckResult:
    status = ctx.probe["status"]
    if status == 402 and ctx.challenge.valid:
        return CheckResult(
            "paywall_present", "Paywall present", "pass",
            detail="Unpaid request drew HTTP 402 with a parseable x402 challenge.",
        )
    if status == 200:
        return CheckResult(
            "paywall_present", "Paywall present", "finding", severity="critical",
            detail="Unpaid request was answered HTTP 200 — the route serves content without payment.",
            fix="Gate the route behind x402 payment middleware so unpaid calls receive a 402 challenge.",
        )
    if status == 402:
        return CheckResult(
            "paywall_present", "Paywall present", "finding", severity="high",
            detail=f"HTTP 402 returned but the challenge is unparseable ({ctx.challenge.error}); conforming x402 clients cannot pay it.",
            fix="Return a well-formed x402 challenge (accepts array with scheme/network/asset/amount/payTo) in the 402 body or payment-required header.",
        )
    return CheckResult(
        "paywall_present", "Paywall present", "finding", severity="high",
        detail=f"Unpaid request drew HTTP {status}, not a 402 x402 challenge.",
        fix="Gate the route behind x402 payment middleware so unpaid calls receive a 402 challenge.",
    )


def _check_challenge_sanity(ctx: _Ctx) -> CheckResult:
    if not ctx.challenge.valid or ctx.primary is None:
        return CheckResult(
            "challenge_sanity", "Challenge sanity", "not_tested",
            detail="No parseable challenge to validate (see paywall_present).",
        )
    a = ctx.primary
    problems: list[str] = []
    if not a.scheme:
        problems.append("accept is missing its scheme")
    if not a.network:
        problems.append("accept is missing its network")
    if not a.asset:
        problems.append("accept is missing its asset")
    elif not (a.asset.startswith("0x") and len(a.asset) == 42):
        problems.append(f"asset {a.asset!r} is not an EVM contract address")
    if not a.pay_to:
        problems.append("accept is missing payTo")
    elif not (a.pay_to.startswith("0x") and len(a.pay_to) == 42):
        problems.append(f"payTo {a.pay_to!r} is not an EVM address")
    amount_int = None
    if a.amount is None:
        problems.append("accept is missing its amount")
    else:
        try:
            amount_int = int(a.amount)
            if amount_int <= 0:
                problems.append(f"amount is {amount_int} — a paid route must charge a positive amount")
        except ValueError:
            problems.append(f"amount {a.amount!r} is not an integer of smallest units")
    if (a.network, (a.asset or "").lower()) not in KNOWN_ASSET_DECIMALS and a.asset:
        problems.append(
            f"asset {a.asset} on {a.network} is not a recognized settlement asset "
            "(LockSmith recognizes USDC on Base; other assets are flagged, not condemned)"
        )
    if problems:
        return CheckResult(
            "challenge_sanity", "Challenge sanity", "finding", severity="medium",
            detail="; ".join(problems) + ".",
            fix="Publish challenge terms that are complete and self-consistent: scheme, CAIP-2 network, the real asset contract, a positive integer amount in smallest units, and your payTo address.",
        )
    return CheckResult(
        "challenge_sanity", "Challenge sanity", "pass",
        detail=(
            f"Challenge terms are complete and consistent: {a.scheme} on {a.network}, "
            f"amount {a.amount} units ({format_price(a.amount, a.network, a.asset) or 'known asset'}), "
            f"payTo {a.pay_to}."
        ),
    )


async def _check_garbage_payment(ctx: _Ctx) -> CheckResult:
    junk = base64.b64encode(b"locksmith-garbage-not-a-payment").decode()
    headers = {
        "user-agent": USER_AGENT,
        "content-type": "application/json",
        "payment-signature": junk,
        "x-payment": junk,
    }
    try:
        if not ctx.budget():
            return CheckResult("garbage_payment", "Garbage payment rejected", "not_tested",
                               detail="Probe budget exhausted before this check could run.")
        status, _h, _b = await fetch(ctx.client, "POST", ctx.target_url, headers, ctx.timeout, content=b"{}")
    except (ProbeRefused, ValueError, httpx.HTTPError) as e:
        return CheckResult("garbage_payment", "Garbage payment rejected", "not_tested",
                           detail=f"Probe could not complete ({type(e).__name__}).")
    if status == 200:
        return CheckResult(
            "garbage_payment", "Garbage payment rejected", "finding", severity="critical",
            detail="A request carrying base64-junk payment headers was answered HTTP 200 — the payment gate accepts anything, or nothing.",
            fix="Verify payments server-side against the facilitator before serving paid content; an unparseable payment header must draw a 402.",
        )
    if status == 402:
        return CheckResult("garbage_payment", "Garbage payment rejected", "pass",
                           detail="Base64-junk payment headers were rejected with a fresh 402 challenge.")
    return CheckResult(
        "garbage_payment", "Garbage payment rejected", "finding", severity="medium",
        detail=f"Junk payment headers drew HTTP {status} instead of a clean 402 rejection.",
        fix="Reject malformed payment headers with a 402 challenge (and no paid content), so clients can retry with a real payment.",
    )


def _chain_id(network: str | None) -> int | None:
    if not network:
        return None
    m = re.fullmatch(r"eip155:(\d+)", network.strip())
    return int(m.group(1)) if m else None


def _forged_payment_header(primary: Any) -> str | None:
    """Build a structurally valid x402 v2 payment payload whose EIP-3009
    authorization carries a signature made over DIFFERENT terms (amount
    +1) — invalid for the target's own challenge, by construction."""
    chain_id = _chain_id(primary.network)
    domain = _EIP712_DOMAINS.get(chain_id or 0)
    if domain is None or not primary.pay_to or not primary.amount:
        return None
    try:
        amount = int(primary.amount)
    except ValueError:
        return None
    # Throwaway key, created per audit and never funded or reused.
    acct = Account.create()
    now = int(time.time())
    message = {
        "from": acct.address,
        "to": primary.pay_to,
        "value": amount,
        "validAfter": 0,
        "validBefore": now + 600,
        "nonce": "0x" + secrets.token_hex(32),
    }
    # Corrupt the signature by re-signing over amount+1: the payload
    # below claims the challenge's amount, the signature covers another.
    wrong = dict(message, value=amount + 1)
    wrong_sig = acct.sign_message(encode_typed_data(domain, _TRANSFER_TYPES, wrong)).signature.hex()
    payload = {
        "x402Version": 2,
        "scheme": primary.scheme or "exact",
        "network": primary.network,
        "payload": {
            "signature": "0x" + wrong_sig,
            "authorization": {
                "from": message["from"],
                "to": message["to"],
                "value": str(message["value"]),
                "validAfter": str(message["validAfter"]),
                "validBefore": str(message["validBefore"]),
                "nonce": message["nonce"],
            },
        },
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


async def _check_forged_payment(ctx: _Ctx) -> CheckResult:
    if not ctx.challenge.valid or ctx.primary is None:
        return CheckResult("forged_payment", "Forged payment rejected", "not_tested",
                           detail="No parseable challenge to forge against (see paywall_present).")
    header = _forged_payment_header(ctx.primary)
    if header is None:
        return CheckResult(
            "forged_payment", "Forged payment rejected", "not_tested",
            detail="LockSmith v1 forges EIP-3009 authorizations only for USDC on Base (eip155:8453); this challenge uses different terms.",
        )
    headers = {
        "user-agent": USER_AGENT,
        "content-type": "application/json",
        "payment-signature": header,
    }
    try:
        if not ctx.budget():
            return CheckResult("forged_payment", "Forged payment rejected", "not_tested",
                               detail="Probe budget exhausted before this check could run.")
        status, _h, _b = await fetch(ctx.client, "POST", ctx.target_url, headers, ctx.timeout, content=b"{}")
    except (ProbeRefused, ValueError, httpx.HTTPError) as e:
        return CheckResult("forged_payment", "Forged payment rejected", "not_tested",
                           detail=f"Probe could not complete ({type(e).__name__}).")
    if status == 200:
        return CheckResult(
            "forged_payment", "Forged payment rejected", "finding", severity="critical",
            detail="A structurally valid EIP-3009 authorization with an INVALID signature was answered HTTP 200 — the route serves paid content without a verified settlement.",
            fix="Settle through the facilitator's verify step and serve content only after a verified, settled payment; never trust the payment header's shape alone.",
        )
    if status in (400, 402, 403):
        return CheckResult("forged_payment", "Forged payment rejected", "pass",
                           detail=f"Invalid-signature EIP-3009 authorization was rejected (HTTP {status}).")
    return CheckResult(
        "forged_payment", "Forged payment rejected", "finding", severity="medium",
        detail=f"Invalid-signature payment drew HTTP {status} instead of a clean rejection.",
        fix="Reject unverifiable payments with a 402 (or 400/403) and no paid content, so clients can retry with a real payment.",
    )


_EXPOSURE_PATHS = [
    ("/.env", "high", re.compile(r"[A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\s*=|-----BEGIN"), "environment file with credential-shaped entries"),
    ("/.git/config", "high", re.compile(r"\[core\]|\[remote"), "git repository config"),
    ("/debug", "medium", re.compile(r"debug|werkzeug|traceback|environment", re.I), "debug surface"),
    ("/metrics", "low", re.compile(r"^#\s*(HELP|TYPE)\s", re.M), "prometheus metrics"),
    ("/admin", "medium", re.compile(r"admin|dashboard|sign in|login", re.I), "admin surface"),
]


async def _check_exposure(ctx: _Ctx) -> CheckResult:
    hits: list[str] = []
    misses = 0
    untested = 0
    for path, severity, pattern, label in _EXPOSURE_PATHS:
        if not ctx.budget():
            untested += 1
            continue
        status, text = await fetch_origin_text(ctx.client, ctx.origin, path, ctx.timeout)
        if status is None:
            untested += 1
            continue
        if status == 200 and pattern.search(text or ""):
            hits.append(f"{path} answered 200 with {label} content ({severity})")
        elif status == 200:
            hits.append(f"{path} answered 200 (content not conclusively sensitive — review manually)")
        else:
            misses += 1
    if hits:
        return CheckResult(
            "exposure_surface", "Exposure surface", "finding",
            severity="high" if any("(high)" in h or "credential" in h for h in hits) else "medium",
            detail="; ".join(hits) + ".",
            fix="Remove or authenticate operational paths (/.env, /.git, /debug, /metrics, /admin) on the public origin; a deploy artifact or debug page is an attacker's map.",
        )
    if untested and not misses:
        return CheckResult("exposure_surface", "Exposure surface", "not_tested",
                           detail="None of the exposure probes could complete (probe budget or target-side refusal).")
    note = f" ({untested} probe(s) could not complete)" if untested else ""
    return CheckResult("exposure_surface", "Exposure surface", "pass",
                       detail=f"None of /.env, /.git/config, /debug, /metrics, /admin answered with sensitive content{note}.")


async def _check_error_hygiene(ctx: _Ctx) -> CheckResult:
    probes = [
        ({"content-type": "application/json"}, b"{not json"),
        ({"content-type": "text/plain"}, b"\x00\x01 plain junk"),
    ]
    leaks: list[str] = []
    inconclusive = 0
    for extra_headers, body in probes:
        headers = {"user-agent": USER_AGENT, **extra_headers}
        try:
            if not ctx.budget():
                inconclusive += 1
                continue
            status, _h, resp_body = await fetch(ctx.client, "POST", ctx.target_url, headers, ctx.timeout, content=body)
        except (ProbeRefused, ValueError, httpx.HTTPError):
            inconclusive += 1
            continue
        # A 402 here means the paywall answered before any body parsing —
        # nothing to judge.
        if status == 402:
            continue
        text = resp_body.decode("utf-8", errors="replace")[:8192]
        for pattern, label in _LEAK_PATTERNS:
            if pattern.search(text):
                leaks.append(f"{label} (HTTP {status})")
                break
    if leaks:
        return CheckResult(
            "error_hygiene", "Error hygiene", "finding", severity="medium",
            detail="Malformed-input error responses leak internals: " + "; ".join(sorted(set(leaks))) + ".",
            fix="Return clean JSON errors (a stable error code/message) for malformed input; keep stack traces, paths, and database detail in server logs only.",
        )
    if inconclusive == len(probes):
        return CheckResult("error_hygiene", "Error hygiene", "not_tested",
                           detail="Both malformed-input probes were cut off before an error body could be judged.")
    return CheckResult("error_hygiene", "Error hygiene", "pass",
                       detail="Malformed-JSON and wrong-content-type requests drew clean errors (or a paywall 402) with no stack traces, paths, SQL, or debug pages.")


async def _check_body_cap(ctx: _Ctx) -> CheckResult:
    junk = b'{"pad":"' + b"x" * (1150 * 1024) + b'"}'
    if not ctx.budget():
        return CheckResult("body_cap", "Body-cap sanity", "not_tested",
                           detail="Probe budget exhausted before this check could run.")
    try:
        result = await send_large_body(ctx.client, ctx.target_url, junk, max(ctx.timeout, 15.0))
    except (ProbeRefused, ValueError) as e:
        # The probe layer itself refused — that is OUR guard, not the
        # target's behaviour; report honestly as not tested.
        return CheckResult("body_cap", "Body-cap sanity", "not_tested",
                           detail=f"Oversized-body probe could not be sent ({e}).")
    if result["refused_early"]:
        return CheckResult("body_cap", "Body-cap sanity", "pass",
                           detail="The target refused/reset the connection while receiving a ~1.1 MiB body instead of swallowing it.")
    status = result["status"]
    if status == 402:
        return CheckResult("body_cap", "Body-cap sanity", "pass",
                           detail="The paywall answered 402 for the oversized request — payment is demanded before body processing runs away.")
    if status in (400, 413):
        return CheckResult("body_cap", "Body-cap sanity", "pass",
                           detail=f"Oversized (~1.1 MiB) body was refused with HTTP {status}.")
    if status == 200:
        return CheckResult(
            "body_cap", "Body-cap sanity", "finding", severity="high",
            detail="A ~1.1 MiB junk body was accepted and answered HTTP 200 — no request-size cap is in force (and payment checks may not be gating this path).",
            fix="Enforce a request-body size cap appropriate to the API (the fleet uses 1 MiB) and reject over-cap requests with 413 before parsing.",
        )
    if status is not None and status >= 500:
        return CheckResult(
            "body_cap", "Body-cap sanity", "finding", severity="medium",
            detail=f"A ~1.1 MiB junk body drew HTTP {status} — the request reached the application and broke something instead of being refused at the door.",
            fix="Enforce a request-body size cap and reject over-cap requests with 413 before they reach application code.",
        )
    if status is not None:
        return CheckResult("body_cap", "Body-cap sanity", "pass",
                           detail=f"Oversized body drew HTTP {status} — refused without content or a crash.")
    return CheckResult("body_cap", "Body-cap sanity", "not_tested",
                       detail=f"Oversized-body probe ended without a readable response ({result['error']}).")


async def _check_discovery(ctx: _Ctx) -> CheckResult:
    found_docs: dict[str, Any] = {}
    for path in ("/.well-known/x402", "/openapi.json"):
        if not ctx.budget():
            break
        # Full body under the probe cap — the 4 KiB snippet used for the
        # exposure check would truncate these documents mid-JSON.
        try:
            status, _h, body = await fetch(
                ctx.client, "GET", ctx.origin + path,
                {"user-agent": USER_AGENT, "accept": "application/json"},
                ctx.timeout,
            )
        except (ProbeRefused, ValueError, httpx.HTTPError):
            continue
        if status == 200 and body:
            try:
                found_docs[path] = json.loads(body)
            except ValueError:
                found_docs[path] = None
    if not found_docs:
        return CheckResult(
            "discovery_consistency", "Discovery consistency", "finding", severity="low",
            detail="Neither /.well-known/x402 nor /openapi.json is published on the target origin — directories and auditors cannot verify the route's advertised terms.",
            fix="Publish a discovery manifest (/.well-known/x402) and OpenAPI document whose route entries and prices match the live 402 challenge.",
        )
    # Find the audited route's advertised accept(s) anywhere in the docs.
    advertised: list[dict] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            res = node.get("resource")
            accepts = node.get("accepts")
            if isinstance(res, str) and res.rstrip("/") == ctx.target_url.rstrip("/") and isinstance(accepts, list):
                advertised.extend(a for a in accepts if isinstance(a, dict))
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    for doc in found_docs.values():
        if isinstance(doc, dict):
            _walk(doc)
    if not advertised:
        present = ", ".join(found_docs)
        return CheckResult(
            "discovery_consistency", "Discovery consistency", "finding", severity="low",
            detail=f"Discovery documents exist ({present}) but neither carries an accepts entry for the audited route — advertised terms cannot be cross-checked against the live challenge.",
            fix="Include the audited route, with its accepts (scheme/network/asset/amount/payTo), in the published discovery manifest.",
        )
    if ctx.primary is None:
        return CheckResult("discovery_consistency", "Discovery consistency", "not_tested",
                           detail="Discovery advertises the route, but there is no parseable live challenge to compare it against.")
    problems: list[str] = []
    matched = False
    for a in advertised:
        adv_amount = a.get("amount") or a.get("maxAmountRequired")
        if (
            str(adv_amount) == str(ctx.primary.amount)
            and a.get("payTo") == ctx.primary.pay_to
            and a.get("network") == ctx.primary.network
        ):
            matched = True
    if not matched:
        problems.append("no advertised accept matches the live challenge's amount/payTo/network")
    if problems:
        return CheckResult(
            "discovery_consistency", "Discovery consistency", "finding", severity="medium",
            detail="; ".join(problems) + " — buyers and directories see different terms than the paywall enforces.",
            fix="Republish the discovery documents so the advertised accepts exactly mirror the live 402 challenge (amount, asset, payTo, network).",
        )
    return CheckResult("discovery_consistency", "Discovery consistency", "pass",
                       detail="Published discovery advertises the audited route with terms matching the live challenge.")


# --- composition --------------------------------------------------------------


def compose_verdict(checks: list[CheckResult]) -> str:
    worst = 0
    for c in checks:
        if c.status == "finding":
            worst = max(worst, _SEVERITY_ORDER.get(c.severity or "low", 1))
    if worst >= 3:
        return "EXPOSED"
    if worst >= 1:
        return "FINDINGS"
    return "SECURE"


async def run_audit(
    target_url: str,
    client: httpx.AsyncClient | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Run the full battery against one x402 endpoint URL.

    Raises ValueError for invalid input (bad URL / non-public host —
    the route answers 422) and AuditUnavailable when the target cannot
    be reached (the route answers 502). Neither settles a payment.
    """
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("endpoint_url must be an http(s) URL")
    # Audit-validity rule: non-public targets are refused up front.
    ssrf_check(target_url)  # raises ValueError

    origin = f"{parsed.scheme}://{parsed.netloc}"
    http = client if client is not None else shared_client()
    ctx = _Ctx(target_url=target_url, origin=origin, timeout=timeout, client=http)

    ctx.probe = await _primary_probe(ctx)
    ctx.challenge = parse_challenge(ctx.probe["status"], ctx.probe["headers"], ctx.probe["body"])
    ctx.primary = ctx.challenge.primary_accept() if ctx.challenge.valid else None

    checks: list[CheckResult] = []
    checks.append(_check_paywall(ctx))
    checks.append(_check_challenge_sanity(ctx))
    checks.append(await _check_garbage_payment(ctx))
    checks.append(await _check_forged_payment(ctx))
    checks.append(await _check_exposure(ctx))
    checks.append(await _check_error_hygiene(ctx))
    checks.append(await _check_body_cap(ctx))
    checks.append(await _check_discovery(ctx))

    findings = [c for c in checks if c.status == "finding"]
    return {
        "ok": True,
        "service": "lock-smith",
        "audit_version": AUDIT_VERSION,
        "target": target_url,
        "verdict": compose_verdict(checks),
        "summary": {
            "passed": sum(1 for c in checks if c.status == "pass"),
            "findings": len(findings),
            "not_tested": sum(1 for c in checks if c.status == "not_tested"),
            "worst_severity": max(
                (c.severity for c in findings),
                key=lambda s: _SEVERITY_ORDER.get(s or "low", 1),
                default=None,
            ),
        },
        "terms_observed": {
            "price": format_price(
                ctx.primary.amount if ctx.primary else None,
                ctx.primary.network if ctx.primary else None,
                ctx.primary.asset if ctx.primary else None,
            ),
            "amount_units": ctx.primary.amount if ctx.primary else None,
            "network": ctx.primary.network if ctx.primary else None,
            "asset": ctx.primary.asset if ctx.primary else None,
            "pay_to": ctx.primary.pay_to if ctx.primary else None,
        },
        "checks": [c.to_dict() for c in checks],
        "probes_used": ctx.probes_used,
        "scope_note": (
            "Automated security checks, not a penetration test. All probes are "
            "unpaid and non-destructive; checks that could not run are reported "
            "as not_tested, never as passes."
        ),
    }
