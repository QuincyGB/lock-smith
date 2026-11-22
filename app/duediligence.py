"""LockSmith due-diligence engines (W2 build, 2026-11-22) — the two
on-chain checks behind POST /v1/approval-check and
POST /v1/contract-check. Read-only toward the chain: JSON-RPC reads
and Blockscout lookups, nothing signed, nothing sent.

Honesty rules (same discipline as app/audit.py): only signals
actually read are reported. The approval check's coverage is BOUNDED
and stated in every response: it enumerates ERC-20 Approval events
for the wallet over a recent window of blocks (the configured
window, echoed back with its from/to blocks) and then reads the
CURRENT allowance for each (token, spender) pair those events name.
An approval granted before the window with no in-window Approval
event is NOT enumerated, and the response says so. Spender risk
flags are labelled heuristics (an unlimited allowance to a plain
EOA, or to a contract whose source Blockscout cannot verify) —
this service keeps no drainer list and never claims one.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .chain import Blockscout, ChainUnavailable, Rpc, is_address

DUE_DILIGENCE_VERSION = "1.0"

# keccak256("Approval(address,address,uint256)") — the ERC-20
# Approval event topic.
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

# eth_getLogs chunk size: public Base RPCs refuse very wide ranges;
# the window is scanned in chunks of this many blocks.
LOG_CHUNK_BLOCKS = 10_000

# Major Base tokens for the fallback scan tier. The broad (unfiltered)
# Approval-event scan is the primary tier, but public RPCs limit it
# (mainnet.base.org rate-limits unfiltered eth_getLogs; publicnode
# refuses unfiltered logs outright — both measured live 2026-11-22).
# The fallback tier scans Approval events per token contract below
# (address-filtered logs, which publicnode serves), and the response
# coverage block names the tier that actually ran.
MAJOR_TOKENS = [
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC
    "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",  # USDT
    "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",  # DAI
    "0x4200000000000000000000000000000000000006",  # WETH
    "0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22",  # cbETH
    "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA",  # USDbC
    "0x940181a94A35A4569E4529A3CDfB74e38FD98631",  # AERO
]
# Cap on distinct (token, spender) pairs followed up with allowance
# reads, so one call's upstream budget stays bounded.
MAX_PAIRS = 50

UINT256_MAX = 2**256 - 1
# At or above 2**255 an allowance is effectively unlimited: no
# realistic spend sequence reaches it.
UNLIMITED_FLOOR = 2**255

# Function selectors.
SEL_ALLOWANCE = "dd62ed3e"  # allowance(address,address)
SEL_SYMBOL = "95d89b41"  # symbol()
SEL_DECIMALS = "313ce567"  # decimals()
SEL_OWNER = "8da5cb5b"  # owner()

# EIP-1967 storage slots.
SLOT_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
ZERO_WORD = "0x" + "0" * 64


def _pad_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def _word_to_address(word: str | None) -> str | None:
    """The address in the low 20 bytes of a 32-byte word, or None
    when the word is empty/zero/unreadable."""
    if not word or not isinstance(word, str) or len(word) < 42:
        return None
    addr = "0x" + word[-40:]
    if not is_address(addr) or int(addr, 16) == 0:
        return None
    return addr


def _decode_string_result(result: str | None) -> str | None:
    """Decode an ABI string return (symbol()); also accepts the
    bytes32 form some older tokens use. None when undecodable."""
    if not result or result == "0x":
        return None
    raw = bytes.fromhex(result[2:])
    try:
        if len(raw) >= 64:
            length = int.from_bytes(raw[32:64], "big")
            return raw[64 : 64 + length].decode("utf-8", errors="strict")
        return raw.rstrip(b"\x00").decode("utf-8", errors="strict") or None
    except (ValueError, UnicodeDecodeError):
        return None


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- approval check -----------------------------------------------------------


async def _token_meta(rpc: Rpc, blockscout: Blockscout, token: str) -> dict:
    """{symbol, decimals} for one token: eth_call first, Blockscout
    as fallback; unknown fields stay None."""
    symbol = _decode_string_result(await rpc.eth_call(token, "0x" + SEL_SYMBOL))
    decimals_raw = await rpc.eth_call(token, "0x" + SEL_DECIMALS)
    decimals = None
    if decimals_raw and decimals_raw != "0x":
        try:
            decimals = int(decimals_raw, 16)
        except ValueError:
            decimals = None
    if symbol is None or decimals is None:
        info = await blockscout.token_info(token)
        if info:
            symbol = symbol if symbol is not None else info["symbol"]
            decimals = decimals if decimals is not None else info["decimals"]
    return {"symbol": symbol, "decimals": decimals}


async def _scan_pairs(
    rpc: Rpc,
    wallet: str,
    from_block: int,
    latest: int,
    *,
    tokens: list[str] | None,
) -> tuple[dict[tuple[str, str], None], int]:
    """Approval-event scan over [from_block, latest] in chunks.
    tokens=None scans every contract's logs (unfiltered); a token
    list scans address-filtered per token. Returns (pairs, chunks)."""
    pairs: dict[tuple[str, str], None] = {}
    chunks = 0
    addresses: list[str | None] = [None] if tokens is None else list(tokens)
    for token_filter in addresses:
        cursor = from_block
        while cursor <= latest:
            chunk_end = min(latest, cursor + LOG_CHUNK_BLOCKS - 1)
            params: dict[str, Any] = {
                "fromBlock": hex(cursor),
                "toBlock": hex(chunk_end),
                "topics": [APPROVAL_TOPIC, _pad_address(wallet)],
            }
            if token_filter is not None:
                params["address"] = token_filter
            logs = await rpc.get_logs(params)
            chunks += 1
            for entry in logs:
                if not isinstance(entry, dict):
                    continue
                token = entry.get("address")
                topics = entry.get("topics") or []
                if not is_address(token) or len(topics) < 3:
                    continue
                spender = _word_to_address(topics[2])
                if spender is None:
                    continue
                pairs.setdefault((token.lower(), spender.lower()))
            cursor = chunk_end + 1
    return pairs, chunks


async def run_approval_check(
    wallet: str,
    *,
    rpc: Rpc,
    blockscout: Blockscout,
    window_blocks: int = 50_000,
    rpc_fallback: Rpc | None = None,
) -> dict[str, Any]:
    """Scan one wallet's risky ERC-20 approvals on Base.

    Raises ValueError for a malformed address (route answers 422)
    and ChainUnavailable when every scan tier fails (route answers
    502). Neither settles a payment.
    """
    if not is_address(wallet):
        raise ValueError("wallet_address must be a 0x-prefixed 20-byte EVM address")
    wallet = wallet.lower()

    latest = await rpc.block_number()
    from_block = max(0, latest - window_blocks + 1)

    # Scan tiers, in order: broad on the primary RPC, broad on the
    # fallback RPC, major-tokens (address-filtered) on the fallback,
    # major-tokens on the primary. The tier that ran is named in the
    # coverage block — a major-token scan never poses as a full scan.
    tiers: list[tuple[str, Rpc, list[str] | None]] = [("all_tokens", rpc, None)]
    if rpc_fallback is not None:
        tiers.append(("all_tokens", rpc_fallback, None))
        tiers.append(("major_tokens", rpc_fallback, MAJOR_TOKENS))
    tiers.append(("major_tokens", rpc, MAJOR_TOKENS))
    pairs: dict[tuple[str, str], None] | None = None
    chunks_scanned = 0
    scan_mode = "all_tokens"
    last_error: ChainUnavailable | None = None
    seen_tiers: set[tuple[int, str]] = set()
    for mode, tier_rpc, tokens in tiers:
        key = (id(tier_rpc), mode)
        if key in seen_tiers:
            continue
        seen_tiers.add(key)
        try:
            pairs, chunks_scanned = await _scan_pairs(
                tier_rpc, wallet, from_block, latest, tokens=tokens
            )
            scan_mode = mode
            break
        except ChainUnavailable as e:
            last_error = e
            pairs = None
    if pairs is None:
        raise ChainUnavailable(
            f"approval event scan failed on every RPC tier: {last_error}"
        )

    approvals: list[dict[str, Any]] = []
    pairs_truncated = len(pairs) > MAX_PAIRS
    for token, spender in list(pairs)[:MAX_PAIRS]:
        data = "0x" + SEL_ALLOWANCE + _pad_address(wallet)[2:] + _pad_address(spender)[2:]
        raw = await rpc.eth_call(token, data)
        if raw is None or raw == "0x":
            continue  # allowance unreadable — not reported as a value
        try:
            allowance = int(raw, 16)
        except ValueError:
            continue
        if allowance == 0:
            continue  # revoked / spent to zero — not a live approval
        meta = await _token_meta(rpc, blockscout, token)
        spender_code = await rpc.get_code(spender)
        spender_is_contract = spender_code not in ("0x", "0x0", "")
        spender_info = await blockscout.address_info(spender)
        spender_sc = await blockscout.smart_contract(spender) if spender_is_contract else None
        spender_verified = spender_sc["is_verified"] if spender_sc else None
        unlimited = allowance >= UNLIMITED_FLOOR
        flags: list[str] = []
        if unlimited:
            flags.append("unlimited_allowance")
        if not spender_is_contract:
            flags.append("spender_is_eoa")
        elif spender_verified is False:
            # Explicitly unverified on the explorer. A None status
            # means the explorer could not be read — unknown, never
            # reported as unverified.
            flags.append("spender_source_unverified")
        elif spender_verified is None and spender_is_contract:
            flags.append("spender_verification_unknown")
        if spender_info is None and spender_sc is None:
            flags.append("spender_unknown_to_explorer")
        if unlimited and ("spender_is_eoa" in flags or "spender_source_unverified" in flags):
            level = "high"
        elif flags:
            level = "medium"
        else:
            level = "low"
        approvals.append(
            {
                "token": token,
                "token_symbol": meta["symbol"],
                "token_decimals": meta["decimals"],
                "spender": spender,
                "spender_is_contract": spender_is_contract,
                "spender_name": (spender_info or {}).get("name") or (spender_sc or {}).get("name"),
                "spender_source_verified": spender_verified,
                "allowance_raw": str(allowance),
                "unlimited": unlimited,
                "risk_flags": flags,
                "risk_level": level,
            }
        )
    approvals.sort(
        key=lambda a: ({"high": 0, "medium": 1, "low": 2}[a["risk_level"]], a["token"])
    )
    risky = [a for a in approvals if a["risk_level"] in ("high", "medium")]
    if any(a["risk_level"] == "high" for a in approvals):
        verdict = "HIGH_RISK"
    elif risky:
        verdict = "FINDINGS"
    elif approvals:
        verdict = "LOW_RISK"
    else:
        verdict = "NO_LIVE_APPROVALS_FOUND"
    scan_note = (
        "The scan covered all token contracts."
        if scan_mode == "all_tokens"
        else (
            "The broad scan was refused by the public RPCs, so the scan "
            "covered only the major token contracts listed in coverage "
            "(scan_mode=major_tokens) — approvals on other tokens are "
            "not enumerated in this response."
        )
    )
    summary = (
        f"Scanned ERC-20 Approval events for this wallet over blocks "
        f"{from_block}-{latest} ({latest - from_block + 1} blocks, Base) and read the "
        f"current allowance for each (token, spender) pair found: "
        f"{len(approvals)} live approval(s), {len(risky)} flagged "
        f"({'unlimited allowance(s) to an EOA or unverified spender present' if verdict == 'HIGH_RISK' else 'see risk_flags per approval'}). "
        f"{scan_note} "
        "Coverage limit: approvals granted before this window with no in-window "
        "Approval event are not enumerated. Spender flags are heuristics from "
        "on-chain and explorer signals — no drainer list is consulted or claimed."
    )
    return {
        "ok": True,
        "service": "lock-smith",
        "check_version": DUE_DILIGENCE_VERSION,
        "wallet": wallet,
        "network": "eip155:8453",
        "verdict": verdict,
        "summary": summary,
        "coverage": {
            "sources": [
                "Base JSON-RPC eth_getLogs (ERC-20 Approval events, owner = wallet)",
                "Base JSON-RPC eth_call allowance(owner, spender) reads at latest block",
                "Base JSON-RPC eth_getCode for spender contract/EOA classification",
                "Blockscout (Base) for spender identity and source-verification status",
            ],
            "window_blocks": latest - from_block + 1,
            "from_block": from_block,
            "to_block": latest,
            "scan_mode": scan_mode,
            "tokens_scanned": "all" if scan_mode == "all_tokens" else MAJOR_TOKENS,
            "log_chunks_scanned": chunks_scanned,
            "pairs_found": len(pairs),
            "pairs_checked": min(len(pairs), MAX_PAIRS),
            "pairs_truncated": pairs_truncated,
            "limitations": (
                "Approvals granted before the window with no in-window Approval "
                "event are not enumerated. Allowances are read at the latest "
                "block only."
            ),
        },
        "approvals": approvals,
        "counts": {
            "live": len(approvals),
            "unlimited": sum(1 for a in approvals if a["unlimited"]),
            "high": sum(1 for a in approvals if a["risk_level"] == "high"),
            "medium": sum(1 for a in approvals if a["risk_level"] == "medium"),
            "low": sum(1 for a in approvals if a["risk_level"] == "low"),
        },
    }


# --- contract check -----------------------------------------------------------


async def run_contract_check(
    address: str,
    *,
    rpc: Rpc,
    blockscout: Blockscout,
) -> dict[str, Any]:
    """Honeypot-adjacent / upgradeability / ownership risk report for
    one Base contract address, from signals actually read: EIP-1967
    proxy slots, owner() presence, Blockscout source verification,
    and contract age. Raises ValueError / ChainUnavailable like the
    approval check."""
    if not is_address(address):
        raise ValueError("contract_address must be a 0x-prefixed 20-byte EVM address")
    address = address.lower()

    code = await rpc.get_code(address)
    is_contract = code not in ("0x", "0x0", "")
    base: dict[str, Any] = {
        "ok": True,
        "service": "lock-smith",
        "check_version": DUE_DILIGENCE_VERSION,
        "contract": address,
        "network": "eip155:8453",
        "is_contract": is_contract,
    }
    if not is_contract:
        return {
            **base,
            "verdict": "NOT_A_CONTRACT",
            "summary": (
                "This address holds no contract code on Base at the latest "
                "block (eth_getCode returned empty), so there is no proxy, "
                "owner, or source to assess. It may be an EOA or an address "
                "on another chain."
            ),
            "signals": {
                "proxy": {"detected": False, "implementation": None, "admin": None, "beacon": None, "explorer_proxy_type": None},
                "ownership": {"owner": None, "admin": None, "has_privileged_role": False},
                "source": {"verified": None, "name": None, "explorer": "blockscout"},
                "age": {"created_at": None, "age_days": None, "creation_transaction": None},
            },
        }

    impl = _word_to_address(await rpc.get_storage_at(address, SLOT_IMPLEMENTATION))
    admin = _word_to_address(await rpc.get_storage_at(address, SLOT_ADMIN))
    beacon = _word_to_address(await rpc.get_storage_at(address, SLOT_BEACON))
    owner_raw = await rpc.eth_call(address, "0x" + SEL_OWNER)
    owner = _word_to_address(owner_raw)

    sc = await blockscout.smart_contract(address)
    info = await blockscout.address_info(address)
    verified = sc["is_verified"] if sc else None
    contract_name = (sc or {}).get("name") or (info or {}).get("name")
    explorer_proxy_type = (sc or {}).get("proxy_type")
    explorer_impls = (sc or {}).get("implementations") or []
    if impl is None and explorer_impls:
        impl = explorer_impls[0].lower()

    created_at: str | None = None
    age_days: int | None = None
    creation_tx = (info or {}).get("creation_transaction_hash")
    created_ts: int | None = None
    ts_raw = (info or {}).get("creation_timestamp")
    if ts_raw:
        try:
            created_ts = int(datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp())
        except ValueError:
            created_ts = None
    if created_ts is None and creation_tx:
        block_num = await rpc.tx_block_number(creation_tx)
        if block_num is not None:
            created_ts = await rpc.block_timestamp(block_num)
    if created_ts is not None:
        created_at = _iso(created_ts)
        age_days = max(0, int((time.time() - created_ts) // 86400))

    proxy_detected = bool(impl or beacon or explorer_proxy_type)
    upgradeable = bool(impl or beacon or admin)
    has_privileged = bool(owner or admin)
    risk_points: list[str] = []
    if upgradeable:
        risk_points.append("upgradeable proxy/admin structure — the code at this address can be replaced by whoever controls the admin/implementation path")
    if has_privileged:
        risk_points.append("a privileged owner/admin address is set — its holder retains control functions")
    if verified is False:
        risk_points.append("source is not verified on Blockscout — the deployed bytecode cannot be matched to published source from the explorer")
    elif verified is None:
        # Explorer unreachable / no record: unknown, not a finding.
        # Stated in the summary via the coverage block, not scored.
        pass
    if age_days is not None and age_days < 30:
        risk_points.append(f"contract is young ({age_days} day(s) old)")
    if upgradeable and has_privileged:
        level = "high"
    elif risk_points:
        level = "medium"
    else:
        level = "low"
    verdict = {"high": "HIGH_RISK", "medium": "FINDINGS", "low": "LOW_RISK"}[level]
    if risk_points:
        summary = "Risk signals read on-chain / from Blockscout: " + "; ".join(risk_points) + "."
    else:
        source_note = (
            "Blockscout verifies the source"
            if verified is True
            else "the source-verification status could not be read from Blockscout (unknown, not counted as verified or unverified)"
        )
        summary = (
            "No proxy or admin structure was read from the EIP-1967 slots, no "
            f"owner() is set, and {source_note}. That is the "
            "absence of the signals this check reads — not a safety guarantee: "
            "this check does not audit contract logic or token transfer rules."
        )
    return {
        **base,
        "verdict": verdict,
        "risk_level": level,
        "summary": summary,
        "signals": {
            "proxy": {
                "detected": proxy_detected,
                "implementation": impl,
                "admin": admin,
                "beacon": beacon,
                "explorer_proxy_type": explorer_proxy_type,
            },
            "ownership": {
                "owner": owner,
                "admin": admin,
                "has_privileged_role": has_privileged,
            },
            "source": {
                "verified": verified,
                "name": contract_name,
                "explorer": "blockscout",
            },
            "age": {
                "created_at": created_at,
                "age_days": age_days,
                "creation_transaction": creation_tx,
            },
        },
        "coverage": {
            "sources": [
                "Base JSON-RPC eth_getCode / eth_getStorageAt (EIP-1967 implementation, admin, beacon slots)",
                "Base JSON-RPC eth_call owner()",
                "Blockscout (Base) smart-contract record (verification, proxy type, implementations) and address record (creation transaction)",
            ],
            "limitations": (
                "Proxy detection reads the EIP-1967 slots and the explorer's "
                "proxy record; non-standard proxy patterns may not be detected. "
                "This check reads structural and ownership signals only — it "
                "does not simulate buys/sells and cannot prove or rule out "
                "honeypot transfer logic."
            ),
        },
    }


def clients_for(
    settings, client: httpx.AsyncClient | None = None
) -> tuple[Rpc, Blockscout, Rpc]:
    """Build the (Rpc, Blockscout, fallback Rpc) triple for one call
    from settings. Tests inject MockTransport clients by constructing
    the clients themselves and passing rpc=/blockscout= (and
    optionally rpc_fallback=) to the engines."""
    http = client if client is not None else httpx.AsyncClient(timeout=20.0)
    return (
        Rpc(http, settings.base_rpc_url),
        Blockscout(http, settings.blockscout_base_url),
        Rpc(http, settings.base_rpc_fallback_url),
    )
