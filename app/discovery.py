"""Agent-discovery surfaces: x402 manifest, skill.md, llms.txt.

Indexers (x402scan, Bazaar, agentic.market) read these alongside the
live 402 responses, so they must stay consistent with main.py pricing.
LockSmith sells security checking, so its own metadata is the showroom:
the output schema is fully typed (never the hollow {"type", "example"}
shape), the shipped example is a REAL audit LockSmith ran against the
fleet's own Token Verdict route (SECURE, 8/8), and every description
stays under the 500-char CDP limit — all pinned by tests.
"""

from __future__ import annotations

from .audit import compactify
from .config import Settings
from .nudge import nudge_extension

# x402 v2 "exact"-scheme asset for USDC on Base mainnet (6 decimals) — the
# real ERC-20 contract address, matching the asset the x402 SDK puts in
# the live 402 payment-required challenge. The manifest must mirror the
# challenge exactly or directory validators reject the mismatch.
USDC_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# x402scan ownership proof: an EIP-191 personal_sign of this service's
# bare origin URL ("https://lock-smith-production.up.railway.app") by
# the payTo wallet, signed by the owner on 2026-10-26 (as he did for
# the other services from 2026-10-24). Published in the manifest below
# and in the OpenAPI x-discovery / x-agentcash-provenance root keys
# (see main.py) so x402scan can verify control of the payment address.
# This is publish-and-verify: the proof must stay published
# permanently — removing it un-verifies the x402scan listing.
# DO NOT REMOVE.
OWNERSHIP_PROOFS: list[str] = [
    "0xa83562902f31c86319b1b60c7ecdcd4662807dd85b91e2547798cccbe1ba5ccb0232a908182471d39f4790aec4614e99246753b0828b1ead407ff465708adc401c"
]


def _price_to_units(price_usdc: str) -> str:
    """'$0.50' -> '500000' (USDC smallest units, 6 decimals)."""
    return str(int(round(float(price_usdc.replace("$", "").strip()) * 1_000_000)))


# --- schemas & example ---------------------------------------------------------

AUDIT_INPUT_SCHEMA = {
    "type": "object",
    "required": ["endpoint_url"],
    "properties": {
        "endpoint_url": {
            "type": "string",
            "description": "Full URL of the x402 endpoint (paid route) to audit, e.g. https://service.example.com/v1/endpoint",
        },
        "mode": {
            "type": "string",
            "enum": ["full", "compact"],
            "default": "full",
            "description": "Response mode. 'full' (default) returns every check's full detail prose. 'compact' returns the same audit with headline summaries for passing checks (findings keep full detail) — for buyers who republish or forward the response; some indexers drop samples over ~1.5 KB.",
        },
    },
}

_CHECK_SCHEMA = {
    "type": "object",
    "required": ["id", "name", "status", "detail"],
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "string", "enum": ["pass", "finding", "not_tested"]},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "detail": {"type": "string"},
        "fix": {"type": "string"},
    },
}

AUDIT_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["ok", "service", "audit_version", "target", "verdict", "summary", "terms_observed", "checks", "probes_used", "scope_note"],
    "properties": {
        "ok": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["full", "compact"]},
        "service": {"type": "string"},
        "audit_version": {"type": "string"},
        "target": {"type": "string"},
        "verdict": {"type": "string", "enum": ["SECURE", "FINDINGS", "EXPOSED"]},
        "summary": {
            "type": "object",
            "properties": {
                "passed": {"type": "integer"},
                "findings": {"type": "integer"},
                "not_tested": {"type": "integer"},
                "worst_severity": {"type": ["string", "null"]},
            },
        },
        "terms_observed": {
            "type": "object",
            "properties": {
                "price": {"type": ["string", "null"]},
                "amount_units": {"type": ["string", "null"]},
                "network": {"type": ["string", "null"]},
                "asset": {"type": ["string", "null"]},
                "pay_to": {"type": ["string", "null"]},
            },
        },
        "checks": {"type": "array", "items": _CHECK_SCHEMA},
        "probes_used": {"type": "integer"},
        "scope_note": {"type": "string"},
    },
}

AUDIT_INPUT_EXAMPLE = {
    "endpoint_url": "https://token-verdict-production.up.railway.app/v1/verdict",
}

# A REAL audit, produced by this service's engine against the fleet's
# own Token Verdict route on 2026-10-25 (SECURE, 8 of 8 checks passed).
# Never hand-edit: regenerate by running the audit.
AUDIT_OUTPUT_EXAMPLE = {'ok': True, 'mode': 'full', 'service': 'lock-smith', 'audit_version': '1.0', 'target': 'https://token-verdict-production.up.railway.app/v1/verdict', 'verdict': 'SECURE', 'summary': {'passed': 8, 'findings': 0, 'not_tested': 0, 'worst_severity': None}, 'terms_observed': {'price': '$0.02', 'amount_units': '20000', 'network': 'eip155:8453', 'asset': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'pay_to': '0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F'}, 'checks': [{'id': 'paywall_present', 'name': 'Paywall present', 'status': 'pass', 'detail': 'Unpaid request drew HTTP 402 with a parseable x402 challenge.'}, {'id': 'challenge_sanity', 'name': 'Challenge sanity', 'status': 'pass', 'detail': 'Challenge terms are complete and consistent: exact on eip155:8453, amount 20000 units ($0.02), payTo 0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F.'}, {'id': 'garbage_payment', 'name': 'Garbage payment rejected', 'status': 'pass', 'detail': 'Base64-junk payment headers were rejected with a fresh 402 challenge.'}, {'id': 'forged_payment', 'name': 'Forged payment rejected', 'status': 'pass', 'detail': 'Invalid-signature EIP-3009 authorization was rejected (HTTP 402).'}, {'id': 'exposure_surface', 'name': 'Exposure surface', 'status': 'pass', 'detail': 'None of /.env, /.git/config, /debug, /metrics, /admin answered with sensitive content.'}, {'id': 'error_hygiene', 'name': 'Error hygiene', 'status': 'pass', 'detail': 'Malformed-JSON and wrong-content-type requests drew clean errors (or a paywall 402) with no stack traces, paths, SQL, or debug pages.'}, {'id': 'body_cap', 'name': 'Body-cap sanity', 'status': 'pass', 'detail': 'Oversized (~1.1 MiB) body was refused with HTTP 413.'}, {'id': 'discovery_consistency', 'name': 'Discovery consistency', 'status': 'pass', 'detail': 'Published discovery advertises the audited route with terms matching the live challenge.'}], 'probes_used': 14, 'scope_note': 'Automated security checks, not a penetration test. All probes are unpaid and non-destructive; checks that could not run are reported as not_tested, never as passes.'}


# The listing publishes the compact pair (ListSmith/Token Verdict
# pattern): Settled's extractor silently drops published output samples
# over ~1.5 KB serialized (measured 2026-10-25), and the honest
# full-mode example above is 2,056 B. The compact example is DERIVED
# from the real full example with the engine's own compactify() — same
# audit, headline pass summaries — and a test pins the derivation and
# the <=1,450 B fleet limit.
AUDIT_COMPACT_INPUT_EXAMPLE = {
    "endpoint_url": "https://token-verdict-production.up.railway.app/v1/verdict",
    "mode": "compact",
}
AUDIT_COMPACT_OUTPUT_EXAMPLE = compactify(AUDIT_OUTPUT_EXAMPLE)


def bazaar_extension(input_schema: dict, output_schema: dict,
                     input_example: dict, output_example: dict) -> dict:
    """The x402 Bazaar discovery extension for the audit route, in the
    canonical v2 shape: `info` carries the values (example input AND a
    full example output with its typed schema); `schema` is the JSON
    Schema OF THE INFO OBJECT (properties input/output), which is what
    facilitator-side validators check info against."""
    return {
        "info": {
            "input": {
                "type": "http",
                "method": "POST",
                "bodyType": "json",
                "body": input_example,
            },
            "output": {
                "type": "json",
                "example": output_example,
                "schema": output_schema,
            },
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "input": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "const": "http"},
                        "method": {"type": "string", "enum": ["POST", "PUT", "PATCH"]},
                        "bodyType": {"type": "string", "enum": ["json", "form-data", "text"]},
                        "body": input_schema,
                    },
                    "required": ["type", "method", "bodyType", "body"],
                    "additionalProperties": False,
                },
                "output": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "example": output_schema,
                        "schema": {"type": "object"},
                    },
                    "required": ["type"],
                },
            },
            "required": ["input"],
        },
    }


def audit_extension() -> dict:
    return bazaar_extension(AUDIT_INPUT_SCHEMA, AUDIT_OUTPUT_SCHEMA,
                             AUDIT_COMPACT_INPUT_EXAMPLE,
                             AUDIT_COMPACT_OUTPUT_EXAMPLE)


def x402_manifest(settings: Settings, base_url: str) -> dict:
    # accepts[] mirrors the live 402 challenge so directory validators
    # (Agent Bazaar, x402scan) accept the manifest.
    def accepts(price: str) -> list[dict]:
        return [
            {
                "scheme": "exact",
                "network": settings.network,
                "amount": _price_to_units(price),
                "asset": USDC_ASSET,
                "payTo": settings.pay_to,
                "maxTimeoutSeconds": 300,
            }
        ]

    return {
        "x402Version": 2,
        "service": settings.service_name,
        "description": (
            "Automated security checks for x402 endpoints — not a "
            "penetration test. POST /v1/audit "
            f"({settings.audit_price_usdc}) runs eight non-destructive, "
            "unpaid probes against one paid route: paywall presence, "
            "challenge sanity, garbage and forged payment rejection, "
            "exposure surface, error hygiene, body-size cap, and "
            "discovery consistency. Returns SECURE / FINDINGS / EXPOSED "
            "with per-check results and a fix note per finding. Use "
            "this when you operate an x402 route and want its locks "
            "checked before an attacker rattles them."
        ),
        "network": settings.network,
        "payTo": settings.pay_to,
        "ownershipProofs": OWNERSHIP_PROOFS,
        # The nudge inbox: this stall accepts signed fleet-health
        # nudges (app/nudge.py; spec in x402-loop-kits). A top-level
        # extension, NOT a resource — inbound mail is free and the
        # priced route count does not move.
        "extensions": {"nudge": nudge_extension(base_url)},
        "resources": [
            {
                "resource": f"{base_url}/v1/audit",
                "method": "POST",
                "price": settings.audit_price_usdc,
                "scheme": "exact",
                "mimeType": "application/json",
                "description": (
                    "Security-audit one x402 endpoint: eight automated, "
                    "non-destructive, unpaid checks (paywall, challenge "
                    "sanity, garbage/forged payment rejection, exposure "
                    "surface, error hygiene, body cap, discovery "
                    "consistency) with a SECURE / FINDINGS / EXPOSED "
                    "verdict and a fix note per finding. Automated "
                    "security checks, not a penetration test."
                ),
                "tags": ["x402", "security", "audit", "agents"],
                "accepts": accepts(settings.audit_price_usdc),
                "inputSchema": AUDIT_INPUT_SCHEMA,
                "outputSchema": AUDIT_OUTPUT_SCHEMA,
            },
            {
                "resource": f"{base_url}/quote",
                "method": "GET",
                "price": "$0.00",
                "description": "Free price quote for the paid endpoints",
            },
        ],
    }



# --- agent card -------------------------------------------------------------
# The A2A-style card served at /.well-known/agent-card.json. It is
# DERIVED from the x402 manifest above — same resources, same prices,
# same payTo — so the card can never drift from the discovery doc the
# directories already read. Skills mirror the priced routes; the
# services[] entries carry each route's endpoint + atomic amount in
# the shape card verifiers (including the fleet's own
# /v1/agent-card-verify on StallRow) read. No capability is claimed
# that the service does not have: no streaming, no A2A task push
# notifications.

CARD_NAME = "LockSmith"
CARD_PROVIDER = {"organization": "Verdict Row", "url": "https://github.com/QuincyGB"}


def _skill_name(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1].replace("-", " ").title()


def agent_card(settings: Settings, base_url: str) -> dict:
    manifest = x402_manifest(settings, base_url)
    skills: list[dict] = []
    services: list[dict] = []
    for r in manifest["resources"]:
        if r.get("method") != "POST":
            continue  # free reads (the quote) are not skills
        resource = r["resource"]
        path = resource[len(base_url):] if resource.startswith(base_url) else resource
        base_accept = next(
            (a for a in r.get("accepts") or [] if a.get("network") == settings.network),
            None,
        )
        skills.append(
            {
                "id": path.strip("/").replace("/", "-"),
                "name": _skill_name(path),
                "description": r["description"],
                "tags": r.get("tags") or [],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        )
        entry = {"name": path, "endpoint": resource}
        if base_accept is not None:
            entry["amount"] = str(base_accept["amount"])
        services.append(entry)
    return {
        "protocolVersion": "0.3.0",
        "name": CARD_NAME,
        "description": manifest["description"],
        "url": base_url,
        "provider": CARD_PROVIDER,
        "version": "1.0.0",
        "documentationUrl": f"{base_url}/llms.txt",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
        "services": services,
        "x402": {
            "version": 2,
            "scheme": "exact",
            "discovery": f"{base_url}/.well-known/x402",
            "payTo": settings.pay_to,
            "network": settings.network,
            "asset": USDC_ASSET,
        },
    }


def skill_md(settings: Settings, base_url: str) -> str:
    return f"""# LockSmith — security audits for x402 endpoints

Automated security checks for one x402 endpoint — **not a penetration
test**. You supply a paid route's URL; LockSmith runs eight
non-destructive, unpaid probes against it and returns a verdict
(SECURE / FINDINGS / EXPOSED), per-check results, and a fix note for
every finding. LockSmith never pays the target; every probe is an
unpaid request.

## Route

`POST {base_url}/v1/audit` — {settings.audit_price_usdc} USDC on Base
(eip155:8453), x402 v2 exact scheme, pay to {settings.pay_to}.

Request body:

```json
{{"endpoint_url": "https://your-service.example.com/v1/route"}}
```

The target must be a public http(s) URL; auditing a non-public address
is refused (422, no settlement). If the target cannot be reached, the
audit answers 502 and the payment does not settle.

## The eight checks

1. **paywall_present** — an unpaid request must draw HTTP 402 with a
   parseable x402 challenge. A 200 unpaid is EXPOSED.
2. **challenge_sanity** — the challenge's scheme, network, asset,
   amount (> 0), and payTo must be complete and self-consistent.
3. **garbage_payment** — base64-junk payment headers must draw a 402.
4. **forged_payment** — a structurally valid EIP-3009 authorization
   with an invalid signature (built from the endpoint's own challenge
   terms) must be rejected.
5. **exposure_surface** — `/.env`, `/.git/config`, `/debug`,
   `/metrics`, `/admin` on the target origin must not serve real
   content.
6. **error_hygiene** — malformed JSON and wrong-content-type requests
   must draw clean errors: no stack traces, file paths, SQL, or debug
   pages.
7. **body_cap** — one ~1.1 MiB junk body must be refused (413/400, an
   early reset, or a paywall 402), not swallowed or crashed on.
8. **discovery_consistency** — published discovery (`/.well-known/x402`,
   `/openapi.json`) must advertise the audited route with terms
   matching the live challenge.

## Honesty

A check that could not run is reported `not_tested` with a reason —
never as a pass. These are automated checks over unpaid probes only:
LockSmith cannot judge authorization logic behind a paywall, business
logic, or anything requiring a real payment to the target. At most ~20
probes are sent per audit.

## Free endpoints

- `GET {base_url}/quote` — price, asset, network, payTo.
- `GET {base_url}/.well-known/x402` — this service's own manifest.
- `GET {base_url}/.well-known/agent-card.json` — A2A agent card (skills mirror the priced routes).
- `GET {base_url}/health` — liveness.
"""


def llms_txt(settings: Settings, base_url: str) -> str:
    return f"""# LockSmith
> Automated security checks for x402 endpoints — not a penetration test. Eight non-destructive, unpaid probes per audit; SECURE / FINDINGS / EXPOSED verdict with fix notes.

- POST {base_url}/v1/audit ({settings.audit_price_usdc} USDC on Base, x402 v2): audit one endpoint URL {{"endpoint_url": "..."}}. Optional "mode": "compact" returns the same audit with headline pass summaries (findings keep full detail).
- GET {base_url}/quote: free price quote.
- GET {base_url}/.well-known/x402: service manifest.
- GET {base_url}/.well-known/agent-card.json: A2A agent card (skills mirror the priced routes).
- GET {base_url}/skill.md: full agent documentation.
"""
