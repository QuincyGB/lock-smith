"""Settings for the lock-smith x402 service."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger("lock-smith.config")

BASE_MAINNET = "eip155:8453"

# His payout wallet on Base (EVM) — the same payTo the whole fleet uses.
# Overridable via X402_PAY_TO.
OWNER_WALLET = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"
PLACEHOLDER_WALLETS = {"0x0000000000000000000000000000000000000000"}

# ultravioletadao public x402 facilitator (no keys). Verified via /supported:
# serves eip155:8453 (Base) with the exact scheme.
FACILITATOR_URL = "https://facilitator.ultravioletadao.xyz"

# PayAI public x402 facilitator (no keys for the exact scheme). Settling
# through it catalogs this service in the PayAI index — each facilitator's
# catalog indexes only its own settlements.
PAYAI_FACILITATOR_URL = "https://facilitator.payai.network"


# Base mainnet JSON-RPC (public node) + Blockscout explorer — the same
# sources the fleet's StallRow stall reads (stall-row app/config.py:
# BASE_RPC_URL https://mainnet.base.org, BLOCKSCOUT_BASE_URL
# https://base.blockscout.com). Used by the due-diligence routes
# (app/duediligence.py) for on-chain approval / contract reads.
BASE_RPC_URL = "https://mainnet.base.org"
# Fallback Base RPC for the approval check's log scans: the primary
# public node rate-limits unfiltered eth_getLogs ("request limit
# reached", measured live 2026-11-22), while publicnode serves
# address-filtered eth_getLogs but refuses unfiltered ones. The
# approval engine tiers across both (see app/duediligence.py).
BASE_RPC_FALLBACK_URL = "https://base-rpc.publicnode.com"
BLOCKSCOUT_BASE_URL = "https://base.blockscout.com"


@dataclass(frozen=True)
class Settings:
    pay_to: str
    audit_price_usdc: str  # e.g. "$0.10" — string format the x402 SDK expects
    network: str
    facilitator_url: str
    service_name: str
    fetch_timeout_s: float  # per-probe timeout for auditing the target
    port: int
    # Coinbase CDP facilitator credentials (optional). Only used when
    # X402_FACILITATOR_URL points at CDP — see use_cdp below.
    # Fleet-internal shared secret (optional). Gates the unpaid
    # /v1/internal/* route that StallRow's /v1/orchestrate fans out
    # to; unset = route disabled (404). Never in discovery.
    fleet_internal_secret: str | None = None
    cdp_api_key_id: str | None = None
    cdp_api_key_secret: str | None = None
    # Due-diligence routes (W2 build, 2026-11-22): POST
    # /v1/approval-check and POST /v1/contract-check prices + the
    # Base chain sources they read (mirrors stall-row app/config.py).
    approval_price_usdc: str = "$0.03"
    contract_price_usdc: str = "$0.10"
    base_rpc_url: str = BASE_RPC_URL
    base_rpc_fallback_url: str = BASE_RPC_FALLBACK_URL
    blockscout_base_url: str = BLOCKSCOUT_BASE_URL
    # Bounded recent window (in blocks) the approval check scans for
    # ERC-20 Approval events — stated in every approval response; a
    # coverage limit, never silently widened.
    approval_window_blocks: int = 50_000

    @property
    def use_cdp(self) -> bool:
        """True when settlements should run through the CDP facilitator
        with JWT auth — the path that feeds the CDP Bazaar catalog. Requires
        BOTH the CDP facilitator URL and API keys; otherwise the keyless
        public facilitator path runs unchanged."""
        return (
            "api.cdp.coinbase.com" in self.facilitator_url
            and bool(self.cdp_api_key_id)
            and bool(self.cdp_api_key_secret)
        )

    @property
    def use_payai(self) -> bool:
        """True when settlements run through the PayAI facilitator — the
        path that feeds the PayAI index catalog. No API key is needed for
        the exact scheme, so the URL alone selects it."""
        return "facilitator.payai.network" in self.facilitator_url


def load_settings() -> Settings:
    pay_to = os.environ.get("X402_PAY_TO", OWNER_WALLET).strip()
    if pay_to in PLACEHOLDER_WALLETS:
        raise RuntimeError("X402_PAY_TO is a placeholder address — set a real wallet.")
    if not (pay_to.startswith("0x") and len(pay_to) == 42):
        raise RuntimeError(f"X402_PAY_TO does not look like an EVM address: {pay_to!r}")

    network = os.environ.get("X402_NETWORK", BASE_MAINNET).strip()
    facilitator_url = os.environ.get("X402_FACILITATOR_URL", FACILITATOR_URL).strip()

    cdp_keys = {
        k: (os.environ.get(k, "").strip() or None)
        for k in ("CDP_API_KEY_ID", "CDP_API_KEY_SECRET")
    }

    return Settings(
        pay_to=pay_to,
        audit_price_usdc=os.environ.get("X402_AUDIT_PRICE_USDC", "$0.10").strip(),
        network=network,
        facilitator_url=facilitator_url,
        service_name=os.environ.get("X402_SERVICE_NAME", "lock-smith").strip(),
        fetch_timeout_s=float(os.environ.get("LOCKSMITH_FETCH_TIMEOUT_S", "8")),
        port=int(os.environ.get("PORT", "3000")),
        fleet_internal_secret=os.environ.get("FLEET_INTERNAL_SECRET", "").strip() or None,
        approval_price_usdc=os.environ.get("X402_APPROVAL_PRICE_USDC", "$0.03").strip(),
        contract_price_usdc=os.environ.get("X402_CONTRACT_PRICE_USDC", "$0.10").strip(),
        base_rpc_url=os.environ.get("BASE_RPC_URL", BASE_RPC_URL).strip(),
        base_rpc_fallback_url=os.environ.get(
            "BASE_RPC_FALLBACK_URL", BASE_RPC_FALLBACK_URL
        ).strip(),
        blockscout_base_url=os.environ.get("BLOCKSCOUT_BASE_URL", BLOCKSCOUT_BASE_URL).strip(),
        approval_window_blocks=int(os.environ.get("LOCKSMITH_APPROVAL_WINDOW_BLOCKS", "50000")),
        **{k.lower(): v for k, v in cdp_keys.items() if v is not None},
    )
