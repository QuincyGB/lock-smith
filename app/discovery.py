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

import json

from .audit import compactify
from .config import Settings
from .evidence import (
    COUNTERPARTY_REPORT_PRICE_USD,
    STALLROW_BASE_URL,
    canonical_input_hash,
)
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
    """'$0.10' -> '100000' (USDC smallest units, 6 decimals)."""
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
        # Delivery extras on every paid response (W2, 2026-11-22).
        "next_check": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "path": {"type": "string"},
                "price_usd": {"type": "number"},
                "service": {"type": "string"},
                "url": {"type": "string"},
            },
        },
        "evidence": {
            "type": "object",
            "properties": {
                "settlement_tx": {"type": ["string", "null"]},
                "input_hash": {"type": "string"},
                "timestamp": {"type": "string"},
            },
        },
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


# --- due-diligence routes (W2 build, 2026-11-22) ------------------------------
# POST /v1/approval-check ($0.03) and POST /v1/contract-check ($0.10):
# read-only on-chain checks over Base RPC + Blockscout. The examples
# below are SCHEMA EXAMPLES (labelled as such in the free samples) —
# shapes with fixture values, not recorded results.

_NEXT_CHECK_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "path": {"type": "string"},
        "price_usd": {"type": "number"},
        "service": {"type": "string"},
        "url": {"type": "string"},
    },
}

_EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "settlement_tx": {"type": ["string", "null"]},
        "input_hash": {"type": "string"},
        "timestamp": {"type": "string"},
    },
}

APPROVAL_INPUT_SCHEMA = {
    "type": "object",
    "required": ["wallet_address"],
    "properties": {
        "wallet_address": {
            "type": "string",
            "description": "Base wallet address (0x-prefixed, 20 bytes) whose ERC-20 token approvals to check, e.g. 0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F",
        },
    },
}

APPROVAL_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["ok", "service", "check_version", "wallet", "network", "verdict", "summary", "coverage", "approvals", "counts"],
    "properties": {
        "ok": {"type": "boolean"},
        "service": {"type": "string"},
        "check_version": {"type": "string"},
        "wallet": {"type": "string"},
        "network": {"type": "string"},
        "verdict": {"type": "string", "enum": ["HIGH_RISK", "FINDINGS", "LOW_RISK", "NO_LIVE_APPROVALS_FOUND"]},
        "summary": {"type": "string"},
        "coverage": {
            "type": "object",
            "properties": {
                "sources": {"type": "array", "items": {"type": "string"}},
                "window_blocks": {"type": "integer"},
                "from_block": {"type": "integer"},
                "to_block": {"type": "integer"},
                "scan_mode": {"type": "string", "enum": ["all_tokens", "major_tokens"]},
                "tokens_scanned": {"type": ["string", "array"]},
                "log_chunks_scanned": {"type": "integer"},
                "pairs_found": {"type": "integer"},
                "pairs_checked": {"type": "integer"},
                "pairs_truncated": {"type": "boolean"},
                "limitations": {"type": "string"},
            },
        },
        "approvals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                    "token_symbol": {"type": ["string", "null"]},
                    "token_decimals": {"type": ["integer", "null"]},
                    "spender": {"type": "string"},
                    "spender_is_contract": {"type": "boolean"},
                    "spender_name": {"type": ["string", "null"]},
                    "spender_source_verified": {"type": ["boolean", "null"]},
                    "allowance_raw": {"type": "string"},
                    "unlimited": {"type": "boolean"},
                    "risk_flags": {"type": "array", "items": {"type": "string"}},
                    "risk_level": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
        "counts": {
            "type": "object",
            "properties": {
                "live": {"type": "integer"},
                "unlimited": {"type": "integer"},
                "high": {"type": "integer"},
                "medium": {"type": "integer"},
                "low": {"type": "integer"},
            },
        },
        "next_check": _NEXT_CHECK_SCHEMA,
        "evidence": _EVIDENCE_SCHEMA,
    },
}

APPROVAL_INPUT_EXAMPLE = {
    "wallet_address": "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F",
}

APPROVAL_OUTPUT_EXAMPLE = {
    "ok": True,
    "service": "lock-smith",
    "check_version": "1.0",
    "wallet": "0x097f9685d1e0752bf8b02d61e5ce9be7ea0fba7f",
    "network": "eip155:8453",
    "verdict": "NO_LIVE_APPROVALS_FOUND",
    "summary": (
        "Scanned ERC-20 Approval events for this wallet over blocks "
        "39000001-39050000 (50000 blocks, Base) and read the current "
        "allowance for each (token, spender) pair found: 0 live "
        "approval(s), 0 flagged. Coverage limit: approvals granted "
        "before this window with no in-window Approval event are not "
        "enumerated."
    ),
    "coverage": {
        "sources": [
            "Base JSON-RPC eth_getLogs (ERC-20 Approval events, owner = wallet)",
            "Base JSON-RPC eth_call allowance(owner, spender) reads at latest block",
            "Base JSON-RPC eth_getCode for spender contract/EOA classification",
            "Blockscout (Base) for spender identity and source-verification status",
        ],
        "window_blocks": 50000,
        "from_block": 39000001,
        "to_block": 39050000,
        "scan_mode": "all_tokens",
        "tokens_scanned": "all",
        "log_chunks_scanned": 5,
        "pairs_found": 0,
        "pairs_checked": 0,
        "pairs_truncated": False,
        "limitations": (
            "Approvals granted before the window with no in-window Approval "
            "event are not enumerated. Allowances are read at the latest "
            "block only."
        ),
    },
    "approvals": [],
    "counts": {"live": 0, "unlimited": 0, "high": 0, "medium": 0, "low": 0},
    "next_check": {
        "name": "counterparty-report",
        "service": "stall-row",
        "path": "/v1/counterparty-report",
        "url": f"{STALLROW_BASE_URL}/v1/counterparty-report",
        "price_usd": COUNTERPARTY_REPORT_PRICE_USD,
    },
    "evidence": {
        "settlement_tx": None,
        "input_hash": canonical_input_hash(APPROVAL_INPUT_EXAMPLE),
        "timestamp": "2026-11-22T00:00:00Z",
    },
}

CONTRACT_INPUT_SCHEMA = {
    "type": "object",
    "required": ["contract_address"],
    "properties": {
        "contract_address": {
            "type": "string",
            "description": "Base contract address (0x-prefixed, 20 bytes) to assess, e.g. 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        },
    },
}

CONTRACT_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["ok", "service", "check_version", "contract", "network", "is_contract", "verdict", "summary", "signals"],
    "properties": {
        "ok": {"type": "boolean"},
        "service": {"type": "string"},
        "check_version": {"type": "string"},
        "contract": {"type": "string"},
        "network": {"type": "string"},
        "is_contract": {"type": "boolean"},
        "verdict": {"type": "string", "enum": ["HIGH_RISK", "FINDINGS", "LOW_RISK", "NOT_A_CONTRACT"]},
        "risk_level": {"type": "string", "enum": ["high", "medium", "low"]},
        "summary": {"type": "string"},
        "signals": {
            "type": "object",
            "properties": {
                "proxy": {
                    "type": "object",
                    "properties": {
                        "detected": {"type": "boolean"},
                        "implementation": {"type": ["string", "null"]},
                        "admin": {"type": ["string", "null"]},
                        "beacon": {"type": ["string", "null"]},
                        "explorer_proxy_type": {"type": ["string", "null"]},
                    },
                },
                "ownership": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": ["string", "null"]},
                        "admin": {"type": ["string", "null"]},
                        "has_privileged_role": {"type": "boolean"},
                    },
                },
                "source": {
                    "type": "object",
                    "properties": {
                        "verified": {"type": ["boolean", "null"]},
                        "name": {"type": ["string", "null"]},
                        "explorer": {"type": "string"},
                    },
                },
                "age": {
                    "type": "object",
                    "properties": {
                        "created_at": {"type": ["string", "null"]},
                        "age_days": {"type": ["integer", "null"]},
                        "creation_transaction": {"type": ["string", "null"]},
                    },
                },
            },
        },
        "coverage": {"type": "object"},
        "next_check": _NEXT_CHECK_SCHEMA,
        "evidence": _EVIDENCE_SCHEMA,
    },
}

CONTRACT_INPUT_EXAMPLE = {
    "contract_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
}

CONTRACT_OUTPUT_EXAMPLE = {
    "ok": True,
    "service": "lock-smith",
    "check_version": "1.0",
    "contract": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "network": "eip155:8453",
    "is_contract": True,
    "verdict": "FINDINGS",
    "risk_level": "medium",
    "summary": (
        "Risk signals read on-chain / from Blockscout: upgradeable "
        "proxy/admin structure — the code at this address can be "
        "replaced by whoever controls the admin/implementation path."
    ),
    "signals": {
        "proxy": {
            "detected": True,
            "implementation": None,
            "admin": None,
            "beacon": None,
            "explorer_proxy_type": "eip1967",
        },
        "ownership": {"owner": None, "admin": None, "has_privileged_role": False},
        "source": {"verified": True, "name": "USD Coin", "explorer": "blockscout"},
        "age": {"created_at": None, "age_days": None, "creation_transaction": None},
    },
    "coverage": {
        "sources": [
            "Base JSON-RPC eth_getCode / eth_getStorageAt (EIP-1967 implementation, admin, beacon slots)",
            "Base JSON-RPC eth_call owner()",
            "Blockscout (Base) smart-contract record (verification, proxy type, implementations) and address record (creation transaction)",
        ],
        "limitations": (
            "Proxy detection reads the EIP-1967 slots and the explorer's "
            "proxy record; non-standard proxy patterns may not be detected."
        ),
    },
    "next_check": {"name": "approval-check", "path": "/v1/approval-check", "price_usd": 0.03},
    "evidence": {
        "settlement_tx": None,
        "input_hash": canonical_input_hash(CONTRACT_INPUT_EXAMPLE),
        "timestamp": "2026-11-22T00:00:00Z",
    },
}


def approval_extension() -> dict:
    return bazaar_extension(
        APPROVAL_INPUT_SCHEMA, APPROVAL_OUTPUT_SCHEMA,
        APPROVAL_INPUT_EXAMPLE, APPROVAL_OUTPUT_EXAMPLE,
    )


def contract_extension() -> dict:
    return bazaar_extension(
        CONTRACT_INPUT_SCHEMA, CONTRACT_OUTPUT_SCHEMA,
        CONTRACT_INPUT_EXAMPLE, CONTRACT_OUTPUT_EXAMPLE,
    )


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
            "LockSmith sells read-only checking for the agent economy "
            "— automated security checks, not a penetration test. "
            f"POST /v1/audit ({settings.audit_price_usdc}) runs eight "
            "non-destructive, unpaid probes against one x402 endpoint. "
            f"POST /v1/approval-check ({settings.approval_price_usdc}) "
            "reads one Base wallet's risky ERC-20 approvals over a "
            f"stated recent block window. POST /v1/contract-check "
            f"({settings.contract_price_usdc}) reports one Base "
            "contract's proxy, ownership, source-verification and age "
            "signals, stating what was actually read."
        ),
        "network": settings.network,
        "payTo": settings.pay_to,
        "ownershipProofs": OWNERSHIP_PROOFS,
        # The nudge inbox: this stall accepts signed fleet-health
        # nudges (app/nudge.py; spec in x402-loop-kits). A top-level
        # extension, NOT a resource — inbound mail is free and the
        # priced route count does not move.
        "extensions": {"nudge": nudge_extension(base_url), "mcp": dict(MCP_SERVER), "quickstart": dict(QUICKSTART), "gradeability": gradeability_extension(base_url), "verdict_row": verdict_row_extension(base_url)},
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
                "tags": ["x402", "security", "audit", "agents", "security-audit", "endpoint-verification", "preflight"],
                "accepts": accepts(settings.audit_price_usdc),
                # The same worked examples the 402 Bazaar extension
                # carries (audit_extension(): the compact pair), embedded
                # in the schemas under the JSON-Schema "example" keyword
                # so manifest-only readers see them too. Copies, not the
                # shared constants, so the schemas published elsewhere
                # (OpenAPI) stay example-free.
                "inputSchema": {
                    **AUDIT_INPUT_SCHEMA,
                    "example": AUDIT_COMPACT_INPUT_EXAMPLE,
                },
                "outputSchema": {
                    **AUDIT_OUTPUT_SCHEMA,
                    "example": AUDIT_COMPACT_OUTPUT_EXAMPLE,
                },
            },
            {
                "resource": f"{base_url}/v1/approval-check",
                "method": "POST",
                "price": settings.approval_price_usdc,
                "scheme": "exact",
                "mimeType": "application/json",
                "description": (
                    "Read one Base wallet's risky ERC-20 token approvals: "
                    "Approval events scanned over a stated recent block "
                    "window, current allowances read on-chain, unlimited "
                    "allowances and allowances to EOAs or unverified "
                    "spender contracts flagged, with a plain risk summary "
                    "and the coverage limits stated in every response."
                ),
                "tags": ["x402", "security", "approvals", "wallet", "base", "due-diligence", "allowances"],
                "accepts": accepts(settings.approval_price_usdc),
                "inputSchema": {
                    **APPROVAL_INPUT_SCHEMA,
                    "example": APPROVAL_INPUT_EXAMPLE,
                },
                "outputSchema": {
                    **APPROVAL_OUTPUT_SCHEMA,
                    "example": APPROVAL_OUTPUT_EXAMPLE,
                },
            },
            {
                "resource": f"{base_url}/v1/contract-check",
                "method": "POST",
                "price": settings.contract_price_usdc,
                "scheme": "exact",
                "mimeType": "application/json",
                "description": (
                    "Structural risk report for one Base contract: "
                    "EIP-1967 proxy implementation/admin/beacon slots, "
                    "owner presence, Blockscout source-verification "
                    "status, and contract age, with a plain risk summary. "
                    "Reports only signals actually read on-chain or from "
                    "the explorer; it does not simulate trades or audit "
                    "contract logic."
                ),
                "tags": ["x402", "security", "contracts", "proxy", "base", "due-diligence", "ownership"],
                "accepts": accepts(settings.contract_price_usdc),
                "inputSchema": {
                    **CONTRACT_INPUT_SCHEMA,
                    "example": CONTRACT_INPUT_EXAMPLE,
                },
                "outputSchema": {
                    **CONTRACT_OUTPUT_SCHEMA,
                    "example": CONTRACT_OUTPUT_EXAMPLE,
                },
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
CARD_PROVIDER = {"organization": "Verdict Row", "url": "https://github.com/QuincyGB", "email": "patrol@verdictrow.com"}

# The MCP server for this stall: a stdio wrapper (source-only — run by
# the caller's own MCP host, not hosted here). Canonical reference is
# the repo and its server.json manifest.
MCP_SERVER = {
    "name": "io.github.QuincyGB/lock-smith-mcp",
    "title": "LockSmith MCP server",
    "transport": "stdio",
    "repository": "https://github.com/QuincyGB/lock-smith-mcp",
    "manifest": "https://github.com/QuincyGB/lock-smith-mcp/blob/main/server.json",
}

# The Inspector Quickstart Pack: one page per language (curl /
# Python / TypeScript), hosted canonically on StallRow at
# /quickstart/<lang>. Every stall links the same canonical pages;
# the URLs are absolute because the pack lives on StallRow's origin
# no matter which stall's discovery doc a reader started from.
QUICKSTART = {
    "title": "Inspector Quickstart Pack",
    "curl": "https://stall-row-production.up.railway.app/quickstart/curl",
    "python": "https://stall-row-production.up.railway.app/quickstart/python",
    "typescript": "https://stall-row-production.up.railway.app/quickstart/typescript",
}

# The Gradeability Self-Test Report: a free public page publishing this
# stall's latest self-test (listed price vs live 402 amount per priced
# route, challenge parse, spec checks, last standing-checker result).
# Committed at app/data/gradeability-report.json, served verbatim at
# /.well-known/gradeability-report.json; linked from the manifest
# extensions, the agent card, skill.md and llms.txt.
GRADEABILITY_REPORT_PATH = "/.well-known/gradeability-report.json"


def gradeability_extension(base_url: str) -> dict:
    return {
        "title": "Gradeability Self-Test Report",
        "report": f"{base_url}{GRADEABILITY_REPORT_PATH}",
    }


# The Fleet Discovery Bundle + the registry-generated A2A dialect card:
# committed at app/data/verdict-row.json and app/data/a2a-agent-card.json
# (generated + bundle signed VM-side by the fleet's discovery_bundle.py
# FROM route_registry.json), served verbatim at
# /.well-known/verdict-row.json and /.well-known/a2a-agent-card.json;
# linked from the manifest extensions, the agent card, skill.md and
# llms.txt. The bundle is ONE signed index of all five stalls — one
# fetch walks the entire row. The A2A card sits ALONGSIDE the existing
# /.well-known/agent-card.json (already A2A-shaped; its path/shape are
# unchanged) for readers that look for an explicitly-named A2A card.
VERDICT_ROW_BUNDLE_PATH = "/.well-known/verdict-row.json"
A2A_AGENT_CARD_PATH = "/.well-known/a2a-agent-card.json"
LLMS_FULL_PATH = "/llms-full.txt"


def verdict_row_extension(base_url: str) -> dict:
    return {
        "title": "Verdict Row Fleet Discovery Bundle + A2A agent card",
        "bundle": f"{base_url}{VERDICT_ROW_BUNDLE_PATH}",
        "a2a_agent_card": f"{base_url}{A2A_AGENT_CARD_PATH}",
    }



_CARD_INPUT_EXAMPLES = {
    "/v1/audit": AUDIT_COMPACT_INPUT_EXAMPLE,
    "/v1/approval-check": APPROVAL_INPUT_EXAMPLE,
    "/v1/contract-check": CONTRACT_INPUT_EXAMPLE,
}


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
                # A2A skill examples: JSON-serialized worked input(s),
                # the StallRow card shape. The audit skill's example is
                # the same input the Bazaar extension / manifest publish.
                "examples": (
                    [json.dumps(_CARD_INPUT_EXAMPLES[path])]
                    if path in _CARD_INPUT_EXAMPLES
                    else []
                ),
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
        "contactEmail": "patrol@verdictrow.com",
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
        "mcp": dict(MCP_SERVER),
        "quickstart": dict(QUICKSTART),
        "gradeability": gradeability_extension(base_url),

        "verdict_row": verdict_row_extension(base_url),
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

## Due-diligence routes (Base, read-only)

`POST {base_url}/v1/approval-check` — {settings.approval_price_usdc} USDC
on Base. Body: `{{"wallet_address": "0x..."}}`. Scans ERC-20 Approval
events for the wallet over a recent block window (default 50,000
blocks; the exact from/to blocks are stated in the response's
`coverage`), reads the current `allowance(owner, spender)` for each
(token, spender) pair found, and flags unlimited allowances plus
allowances to EOAs or spender contracts whose source is not verified
on Blockscout. Approvals granted before the window with no in-window
Approval event are NOT enumerated — the response says so.

`POST {base_url}/v1/contract-check` — {settings.contract_price_usdc}
USDC on Base. Body: `{{"contract_address": "0x..."}}`. Reports the
signals actually read: EIP-1967 implementation/admin/beacon slots
(proxy + upgradeability), `owner()` presence, Blockscout
source-verification status, and contract age, with a plain risk
summary. It does not simulate buys/sells and cannot prove or rule
out honeypot transfer logic.

Every paid response (all three routes) carries `next_check` (one
suggested follow-up route with its price) and `evidence`
(`settlement_tx` when a settlement receipt exists, the sha256
`input_hash` of the canonical request input, and the delivery
`timestamp`).

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
- `GET {base_url}/.well-known/stability-manifest.json` — signed pinned-route stability manifest (prices + schema fingerprints, pinned under an agent-wallet signature).
- `GET {base_url}/.well-known/gradeability-report.json` — Gradeability Self-Test Report (latest self-test: listed price vs live 402 per priced route, challenge parse, spec checks, standing-checker result; signed, free)
- `GET {base_url}/.well-known/verdict-row.json` — Verdict Row Fleet Discovery Bundle (signed index of all five stalls: discovery docs, stability manifests, agent cards, gradeability reports, MCP server.json, fleet tools/status and feeds; one fetch walks the whole row, free)
- `GET {base_url}/.well-known/a2a-agent-card.json` — A2A agent card (registry-generated dialect twin of /.well-known/agent-card.json: skills mirror the priced routes at their registry prices, free)
- `GET {base_url}/llms-full.txt` — llms-full.txt, the long-form companion to llms.txt (full route docs with worked request/response examples, pack mechanics, Recheck feed + hash-chain spec, watch/corrections policy; generated from the fleet route registry, free)
- MCP server (stdio, run it in your own MCP host): https://github.com/QuincyGB/lock-smith-mcp — manifest (server.json): https://github.com/QuincyGB/lock-smith-mcp/blob/main/server.json — tools wrap the priced route (/v1/audit)
- Inspector Quickstart Pack (curl / Python / TypeScript): https://stall-row-production.up.railway.app/quickstart/curl · https://stall-row-production.up.railway.app/quickstart/python · https://stall-row-production.up.railway.app/quickstart/typescript — one-page integration path: pin Recheck + RouteVerdict, read the feed, register a watch, fund a pack
- Verdict Row Tools Index: https://stall-row-production.up.railway.app/tools — every stall, every priced route + price, key surfaces (agent card, stability manifest, gradeability report, MCP, SDK status); machine-readable: https://stall-row-production.up.railway.app/tools.json
- Verdict Row Fleet Status: https://stall-row-production.up.railway.app/status — last-check status for every priced route in the fleet, rendered from the standing checker's own state (snapshot, timestamps on the page; JSON twin: https://stall-row-production.up.railway.app/status.json)
- Free samples: `GET {base_url}/samples` — one sample response per priced route on this stall (recorded responses and schema-examples, labelled in-band: sample=true, live=false); `GET {base_url}/sample/<route-slug>` for a single route
- Sandbox twins (free): `GET {base_url}/sandbox` lists a free sandbox twin of every priced route on this stall — POST to {base_url}/sandbox plus the priced route's path (same request schema and validation, no payment leg, deterministic fixture delivery marked sandbox=true, never a real delivery); edge-case scenarios normal / rotated_payto / drifted_schema / flagged_wallet via the X-Sandbox-Scenario header
- Verdict Row Public Changelog: https://stall-row-production.up.railway.app/changelog.atom — subscribable Atom feed of fleet route / price / stability-manifest changes (JSON twin: https://stall-row-production.up.railway.app/changelog.json)
- `GET {base_url}/health` — liveness.
"""


def llms_txt(settings: Settings, base_url: str) -> str:
    return f"""# LockSmith
> Automated security checks for x402 endpoints — not a penetration test. Eight non-destructive, unpaid probes per audit; SECURE / FINDINGS / EXPOSED verdict with fix notes.

- POST {base_url}/v1/audit ({settings.audit_price_usdc} USDC on Base, x402 v2): audit one endpoint URL {{"endpoint_url": "..."}}. Optional "mode": "compact" returns the same audit with headline pass summaries (findings keep full detail).
- POST {base_url}/v1/approval-check ({settings.approval_price_usdc} USDC on Base, x402 v2): check one wallet's risky ERC-20 approvals {{"wallet_address": "0x..."}} — Approval events over a stated recent block window (default 50,000 blocks) + current allowance reads; unlimited allowances and EOAs/unverified spenders flagged; pre-window approvals are not enumerated.
- POST {base_url}/v1/contract-check ({settings.contract_price_usdc} USDC on Base, x402 v2): structural risk report for one contract {{"contract_address": "0x..."}} — EIP-1967 proxy slots, owner presence, Blockscout source verification, contract age. Every paid response carries next_check + evidence (settlement_tx / input_hash / timestamp).
- GET {base_url}/quote: free price quote.
- GET {base_url}/.well-known/x402: service manifest.
- GET {base_url}/.well-known/agent-card.json: A2A agent card (skills mirror the priced routes).
- GET {base_url}/.well-known/stability-manifest.json: signed pinned-route stability manifest (prices + schema fingerprints).
- GET {base_url}/.well-known/gradeability-report.json — Gradeability Self-Test Report (latest self-test: listed vs live 402 per priced route; signed, free)
- GET {base_url}/.well-known/verdict-row.json — Verdict Row Fleet Discovery Bundle (signed index of all five stalls: discovery docs, stability manifests, agent cards, gradeability reports, MCP server.json, fleet tools/status and feeds; one fetch walks the whole row, free)
- GET {base_url}/.well-known/a2a-agent-card.json — A2A agent card (registry-generated dialect twin of /.well-known/agent-card.json: skills mirror the priced routes at their registry prices, free)
- GET {base_url}/llms-full.txt — llms-full.txt, the long-form companion to llms.txt (full route docs with worked request/response examples, pack mechanics, Recheck feed + hash-chain spec, watch/corrections policy; generated from the fleet route registry, free)
- MCP server (stdio, run it in your own MCP host): https://github.com/QuincyGB/lock-smith-mcp — manifest (server.json): https://github.com/QuincyGB/lock-smith-mcp/blob/main/server.json — tools wrap the priced route (/v1/audit)
- Inspector Quickstart Pack (curl / Python / TypeScript): https://stall-row-production.up.railway.app/quickstart/curl · https://stall-row-production.up.railway.app/quickstart/python · https://stall-row-production.up.railway.app/quickstart/typescript — one-page integration path: pin Recheck + RouteVerdict, read the feed, register a watch, fund a pack
- Verdict Row Tools Index: https://stall-row-production.up.railway.app/tools — every stall, every priced route + price, key surfaces (agent card, stability manifest, gradeability report, MCP, SDK status); machine-readable: https://stall-row-production.up.railway.app/tools.json
- Verdict Row Fleet Status: https://stall-row-production.up.railway.app/status — last-check status for every priced route in the fleet, rendered from the standing checker's own state (snapshot, timestamps on the page; JSON twin: https://stall-row-production.up.railway.app/status.json)
- Free samples: `GET {base_url}/samples` — one sample response per priced route on this stall (recorded responses and schema-examples, labelled in-band: sample=true, live=false); `GET {base_url}/sample/<route-slug>` for a single route
- Sandbox twins (free): `GET {base_url}/sandbox` lists a free sandbox twin of every priced route on this stall — POST to {base_url}/sandbox plus the priced route's path (same request schema and validation, no payment leg, deterministic fixture delivery marked sandbox=true, never a real delivery); edge-case scenarios normal / rotated_payto / drifted_schema / flagged_wallet via the X-Sandbox-Scenario header
- Verdict Row Public Changelog: https://stall-row-production.up.railway.app/changelog.atom — subscribable Atom feed of fleet route / price / stability-manifest changes (JSON twin: https://stall-row-production.up.railway.app/changelog.json)
- GET {base_url}/skill.md: full agent documentation.
"""
