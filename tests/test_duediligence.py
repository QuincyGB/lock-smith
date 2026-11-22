"""Due-diligence routes (W2 build, 2026-11-22): POST
/v1/approval-check ($0.03) and POST /v1/contract-check ($0.10).

Offline throughout: the engines run against httpx.MockTransport
upstreams (a scripted Base JSON-RPC + Blockscout), the paywall is
exercised unpaid (402 challenges carry the exact prices), and the
handlers are called directly with the engine monkeypatched to prove
the delivery extras (next_check + evidence) attach. No real payment
is ever made.
"""

import base64
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.chain import Blockscout, Rpc
from app.duediligence import (
    APPROVAL_TOPIC,
    SLOT_ADMIN,
    SLOT_IMPLEMENTATION,
    run_approval_check,
    run_contract_check,
)
from app.evidence import canonical_input_hash

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
OWNER = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"
WALLET = "0x1111111111111111111111111111111111111111"
SPENDER_EOA = "0x2222222222222222222222222222222222222222"
SPENDER_CONTRACT = "0x3333333333333333333333333333333333333333"
TOKEN = "0x4444444444444444444444444444444444444444"
IMPL = "0x5555555555555555555555555555555555555555"
ADMIN = "0x6666666666666666666666666666666666666666"
UINT256_MAX = 2**256 - 1
LATEST_BLOCK = 40_000


def _word(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def _pad_topic(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


class FakeChain:
    """Scripted Base RPC + Blockscout over one MockTransport.

    RPC behaviour:
    - eth_blockNumber -> LATEST_BLOCK
    - eth_getLogs -> one Approval event (WALLET -> SPENDER_EOA on
      TOKEN) in the first chunk, empty afterwards
    - eth_call allowance -> uint256 max (unlimited); symbol ->
      "TOK"; decimals -> 6; owner() -> ADMIN word for the contract
      under test, revert (JSON-RPC error) otherwise
    - eth_getCode -> bytecode for SPENDER_CONTRACT and the contract
      under test, "0x" otherwise
    - eth_getStorageAt -> implementation/admin slots set for the
      contract under test
    Blockscout: spender EOA unknown (404 JSON), spender contract
    unverified, contract under test verified + eip1967 proxy record,
    token info present.
    """

    def __init__(self, contract: str):
        self.contract = contract.lower()
        self.transport = httpx.MockTransport(self._handle)
        self.client = httpx.AsyncClient(transport=self.transport, base_url="http://chain.test")

    def rpc(self) -> Rpc:
        return Rpc(self.client, "http://chain.test/rpc")

    def blockscout(self) -> Blockscout:
        return Blockscout(self.client, "http://chain.test")

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/rpc":
            return self._rpc(request)
        if path.startswith("/api/v2/addresses/"):
            addr = path.rsplit("/", 1)[-1].lower()
            if addr == SPENDER_CONTRACT.lower():
                return httpx.Response(200, json={"is_contract": True, "name": None})
            if addr == self.contract:
                return httpx.Response(
                    200,
                    json={
                        "is_contract": True,
                        "name": "Fixture Token",
                        "creation_transaction_hash": "0x" + "ab" * 32,
                        "creation_timestamp": "2025-01-01T00:00:00Z",
                    },
                )
            return httpx.Response(404, json={"message": "not found"})
        if path.startswith("/api/v2/smart-contracts/"):
            addr = path.rsplit("/", 1)[-1].lower()
            if addr == self.contract:
                return httpx.Response(
                    200,
                    json={
                        "is_verified": True,
                        "name": "Fixture Token",
                        "proxy_type": "eip1967",
                        "implementations": [{"address_hash": IMPL}],
                    },
                )
            if addr == SPENDER_CONTRACT.lower():
                return httpx.Response(200, json={"is_verified": False, "name": None})
            return httpx.Response(404, json={"message": "not found"})
        if path.startswith("/api/v2/tokens/"):
            return httpx.Response(200, json={"symbol": "TOK", "name": "Token", "decimals": "6"})
        return httpx.Response(404, json={"message": "unhandled"})

    def _rpc(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body.get("params") or []

        def ok(result):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

        def err(message="execution reverted"):
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": 3, "message": message}}
            )

        if method == "eth_blockNumber":
            return ok(hex(LATEST_BLOCK))
        if method == "eth_getLogs":
            f = params[0]
            if int(f["toBlock"], 16) != LATEST_BLOCK:
                return ok([])
            return ok(
                [
                    {
                        "address": TOKEN,
                        "topics": [APPROVAL_TOPIC, _pad_topic(WALLET), _pad_topic(SPENDER_EOA)],
                        "data": "0x" + format(UINT256_MAX, "064x"),
                    },
                    {
                        "address": TOKEN,
                        "topics": [APPROVAL_TOPIC, _pad_topic(WALLET), _pad_topic(SPENDER_CONTRACT)],
                        "data": "0x" + format(1000, "064x"),
                    },
                ]
            )
        if method == "eth_getCode":
            addr = params[0].lower()
            if addr in (SPENDER_CONTRACT.lower(), self.contract):
                return ok("0x6080604052")
            return ok("0x")
        if method == "eth_getStorageAt":
            addr, slot = params[0].lower(), params[1].lower()
            if addr == self.contract and slot == SLOT_IMPLEMENTATION.lower():
                return ok(_word(IMPL))
            if addr == self.contract and slot == SLOT_ADMIN.lower():
                return ok(_word(ADMIN))
            return ok("0x" + "0" * 64)
        if method == "eth_call":
            call = params[0]
            to, data = call["to"].lower(), call["data"]
            if data.startswith("0xdd62ed3e"):  # allowance
                spender = "0x" + data[-40:]
                if spender == SPENDER_EOA.lower():
                    return ok("0x" + format(UINT256_MAX, "064x"))
                return ok("0x" + format(1000, "064x"))
            if data.startswith("0x95d89b41"):  # symbol()
                raw = b"TOK"
                return ok("0x" + (32).to_bytes(32, "big").hex() + len(raw).to_bytes(32, "big").hex() + raw.hex().ljust(64, "0"))
            if data.startswith("0x313ce567"):  # decimals()
                return ok("0x" + format(6, "064x"))
            if data.startswith("0x8da5cb5b"):  # owner()
                if to == self.contract:
                    return ok(_word(ADMIN))
                return err()
            return err()
        if method == "eth_getTransactionByHash":
            return ok({"blockNumber": hex(LATEST_BLOCK - 100)})
        if method == "eth_getBlockByNumber":
            return ok({"timestamp": hex(1735689600)})  # 2025-01-01T00:00:00Z
        return err(f"unhandled method {method}")


# --- engine: approval check ---------------------------------------------------


@pytest.mark.asyncio
async def test_approval_check_flags_unlimited_eoa_and_unverified_spender():
    fake = FakeChain(contract=USDC)
    result = await run_approval_check(
        WALLET, rpc=fake.rpc(), blockscout=fake.blockscout(), window_blocks=500
    )
    assert result["verdict"] == "HIGH_RISK"
    assert result["counts"] == {"live": 2, "unlimited": 1, "high": 1, "medium": 1, "low": 0}
    by_spender = {a["spender"]: a for a in result["approvals"]}
    eoa = by_spender[SPENDER_EOA.lower()]
    assert eoa["unlimited"] is True
    assert eoa["spender_is_contract"] is False
    assert "unlimited_allowance" in eoa["risk_flags"]
    assert "spender_is_eoa" in eoa["risk_flags"]
    assert eoa["risk_level"] == "high"
    assert eoa["token_symbol"] == "TOK"
    assert eoa["token_decimals"] == 6
    contract_spender = by_spender[SPENDER_CONTRACT.lower()]
    assert contract_spender["spender_is_contract"] is True
    assert contract_spender["spender_source_verified"] is False
    assert "spender_source_unverified" in contract_spender["risk_flags"]
    # Coverage is stated, bounded, and honest about its limit.
    cov = result["coverage"]
    assert cov["to_block"] == LATEST_BLOCK
    assert cov["window_blocks"] == 500
    assert cov["pairs_found"] == 2
    assert "not enumerated" in cov["limitations"]
    assert "not enumerated" in result["summary"]


@pytest.mark.asyncio
async def test_approval_check_falls_back_to_major_token_scan():
    """When the broad scan is refused (the public-RPC rate-limit
    shape measured live), the engine tiers down to address-filtered
    scans of the major tokens and NAMES that tier in coverage."""

    class RefusingRpc:
        async def block_number(self):
            return LATEST_BLOCK

        async def get_logs(self, params):
            from app.chain import ChainUnavailable

            raise ChainUnavailable("request limit reached")

        async def eth_call(self, to, data):
            return None

        async def get_code(self, address):
            return "0x"

    fake = FakeChain(contract=USDC)
    result = await run_approval_check(
        WALLET,
        rpc=RefusingRpc(),
        blockscout=fake.blockscout(),
        window_blocks=500,
        rpc_fallback=fake.rpc(),
    )
    # The fallback's unfiltered tier is refused by the fake? No — the
    # fake serves logs for any filter; its broad tier answers, so the
    # mode stays all_tokens. The major-token tier is exercised below
    # with a fallback that refuses unfiltered logs.
    assert result["coverage"]["scan_mode"] in ("all_tokens", "major_tokens")

    class AddressFilteredOnly:
        """publicnode's shape: unfiltered eth_getLogs is refused,
        address-filtered logs are served (delegated to the fake)."""

        def __init__(self, inner):
            self._inner = inner

        async def block_number(self):
            return LATEST_BLOCK

        async def get_logs(self, params):
            from app.chain import ChainUnavailable

            if "address" not in params:
                raise ChainUnavailable("specify an address")
            return await self._inner.get_logs(params)

        async def eth_call(self, to, data):
            return await self._inner.eth_call(to, data)

        async def get_code(self, address):
            return await self._inner.get_code(address)

    result = await run_approval_check(
        WALLET,
        rpc=RefusingRpc(),
        blockscout=fake.blockscout(),
        window_blocks=500,
        rpc_fallback=AddressFilteredOnly(fake.rpc()),
    )
    assert result["coverage"]["scan_mode"] == "major_tokens"
    assert "major_tokens" in result["summary"]


@pytest.mark.asyncio
async def test_approval_check_rejects_bad_address():
    fake = FakeChain(contract=USDC)
    with pytest.raises(ValueError):
        await run_approval_check("not-an-address", rpc=fake.rpc(), blockscout=fake.blockscout())


# --- engine: contract check ---------------------------------------------------


@pytest.mark.asyncio
async def test_contract_check_reads_proxy_owner_source_and_age():
    fake = FakeChain(contract=USDC)
    result = await run_contract_check(USDC, rpc=fake.rpc(), blockscout=fake.blockscout())
    assert result["is_contract"] is True
    signals = result["signals"]
    assert signals["proxy"]["detected"] is True
    assert signals["proxy"]["implementation"] == IMPL.lower()
    assert signals["proxy"]["admin"] == ADMIN.lower()
    assert signals["ownership"]["owner"] == ADMIN.lower()
    assert signals["ownership"]["has_privileged_role"] is True
    assert signals["source"]["verified"] is True
    assert signals["age"]["created_at"] == "2025-01-01T00:00:00Z"
    assert signals["age"]["age_days"] > 300
    assert result["verdict"] == "HIGH_RISK"
    assert "does not simulate" in result["coverage"]["limitations"]


@pytest.mark.asyncio
async def test_contract_check_eoa_address_is_not_a_contract():
    fake = FakeChain(contract=USDC)
    result = await run_contract_check(WALLET, rpc=fake.rpc(), blockscout=fake.blockscout())
    assert result["is_contract"] is False
    assert result["verdict"] == "NOT_A_CONTRACT"


# --- paywall ------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    return TestClient(main.app, raise_server_exceptions=False)


def _challenge(response):
    raw = response.headers.get("payment-required")
    assert raw, "402 response must carry a payment-required header"
    return json.loads(base64.b64decode(raw))


@pytest.mark.parametrize(
    "path,body,amount",
    [
        ("/v1/approval-check", {"wallet_address": WALLET}, "30000"),
        ("/v1/contract-check", {"contract_address": USDC}, "100000"),
    ],
)
def test_unpaid_duediligence_routes_are_paywalled_at_their_prices(client, path, body, amount):
    r = client.post(path, json=body)
    assert r.status_code == 402
    challenge = _challenge(r)
    (accept,) = challenge["accepts"]
    assert accept["scheme"] == "exact"
    assert accept["network"] == "eip155:8453"
    assert accept["asset"] == USDC
    assert accept["amount"] == amount
    assert accept["payTo"] == OWNER
    # The 402 body mirrors the challenge (Market402 compatibility).
    assert r.json()["accepts"][0]["amount"] == amount
    # Bazaar extension carries a worked input example.
    info = challenge["extensions"]["bazaar"]["info"]
    assert info["input"]["body"]
    assert info["output"]["example"]["ok"] is True


def test_descriptions_screening_safe_and_under_500():
    for text in (main.APPROVAL_DESCRIPTION, main.CONTRACT_DESCRIPTION):
        assert len(text) <= 500
        assert "guarantee" not in text.lower()


def test_price_units_match_settings():
    assert main.PRICE_UNITS["/v1/approval-check"] == 30_000
    assert main.PRICE_UNITS["/v1/contract-check"] == 100_000
    assert main.settings.approval_price_usdc == "$0.03"
    assert main.settings.contract_price_usdc == "$0.10"


def test_quote_lists_all_paid_routes(client):
    body = client.get("/quote").json()
    assert body["endpoints"]["/v1/approval-check"]["price"] == "$0.03"
    assert body["endpoints"]["/v1/contract-check"]["price"] == "$0.10"


# --- handlers: next_check + evidence ------------------------------------------


@pytest.mark.asyncio
async def test_handlers_attach_next_check_and_evidence(monkeypatch):
    async def fake_approval(wallet, *, rpc, blockscout, window_blocks, rpc_fallback=None):
        return {"ok": True, "wallet": wallet.lower()}

    async def fake_contract(address, *, rpc, blockscout):
        return {"ok": True, "contract": address.lower()}

    monkeypatch.setattr(main, "run_approval_check", fake_approval)
    monkeypatch.setattr(main, "run_contract_check", fake_contract)

    out = await main.approval_check(main.ApprovalCheckRequest(wallet_address=WALLET))
    assert out["next_check"]["name"] == "counterparty-report"
    assert out["next_check"]["path"] == "/v1/counterparty-report"
    assert out["next_check"]["price_usd"] == 0.10
    assert out["evidence"]["settlement_tx"] is None  # filled at the delivery layer
    assert out["evidence"]["input_hash"] == canonical_input_hash({"wallet_address": WALLET.lower()})
    assert out["evidence"]["timestamp"].endswith("Z")

    out = await main.contract_check(main.ContractCheckRequest(contract_address=USDC))
    assert out["next_check"] == {
        "name": "approval-check",
        "path": "/v1/approval-check",
        "price_usd": 0.03,
    }
    assert out["evidence"]["input_hash"] == hashlib.sha256(
        json.dumps({"contract_address": USDC.lower()}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@pytest.mark.asyncio
async def test_audit_handler_attaches_next_check_and_evidence(monkeypatch):
    async def fake_audit(url, *, timeout, mode):
        return {"ok": True, "target": url, "mode": mode}

    monkeypatch.setattr(main, "run_audit", fake_audit)
    out = await main.audit(
        main.AuditRequest(endpoint_url="https://target.example.com/v1/thing")
    )
    assert out["next_check"] == {
        "name": "approval-check",
        "path": "/v1/approval-check",
        "price_usd": 0.03,
    }
    assert out["evidence"]["settlement_tx"] is None
    assert out["evidence"]["input_hash"] == canonical_input_hash(
        {"endpoint_url": "https://target.example.com/v1/thing", "mode": "full"}
    )


def test_evidence_settlement_tx_filled_from_receipt_at_delivery_layer():
    # The delivery layer fills settlement_tx from the payment-response
    # receipt header — simulate the loop/evidence attach on a settled
    # per-call-shaped response.
    import asyncio

    receipt = {"payer": WALLET, "transaction": "0x" + "cd" * 32, "network": "eip155:8453"}
    body = json.dumps(
        {
            "ok": True,
            "evidence": {"settlement_tx": None, "input_hash": "ab" * 32, "timestamp": "2026-11-22T00:00:00Z"},
        }
    ).encode()
    from starlette.responses import Response

    response = Response(content=body, media_type="application/json")
    response.headers["payment-response"] = base64.b64encode(json.dumps(receipt).encode()).decode()

    class _Req:
        method = "POST"

        class url:
            path = "/v1/audit"

    out = asyncio.run(main._attach_loop_offer(_Req(), response))
    data = json.loads(out.body)
    assert data["evidence"]["settlement_tx"] == "0x" + "cd" * 32
    assert "verdict_row_loop" in data
