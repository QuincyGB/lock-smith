"""Base chain reads for the due-diligence routes — a minimal JSON-RPC
client plus a Blockscout (Base) v2 client.

Patterns mirrored from the fleet's StallRow stall (stall-row
app/rpc.py and app/blockscout.py — copied patterns, no cross-repo
import): every client takes an injectable httpx.AsyncClient so tests
play upstreams through httpx.MockTransport with zero network; RPC
failures raise ChainUnavailable (handlers answer 502, which never
settles a payment); Blockscout methods return None on ANY failure —
base.blockscout.com intermittently answers with a Cloudflare
challenge page instead of JSON — and callers mark the affected
fields unknown. Nothing here fabricates an on-chain or explorer
field.
"""

from __future__ import annotations

import asyncio
import itertools

import httpx

_UA = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    ),
    "Accept": "application/json",
}


class ChainUnavailable(Exception):
    """An upstream chain read failed or returned unusable data.
    The route maps this to 502 — the caller's payment never settles."""


def is_address(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) == 42
        and all(c in "0123456789abcdefABCDEF" for c in value[2:])
    )


class Rpc:
    """Minimal Base JSON-RPC client over an injectable httpx client
    (mirrors stall-row app/rpc.py, trimmed to the calls the
    due-diligence routes make)."""

    def __init__(self, client: httpx.AsyncClient, url: str):
        self._client = client
        self._url = url
        self._ids = itertools.count(1)

    async def call(self, method: str, params: list) -> object:
        """One JSON-RPC call, with ONE retry on transient failures
        (transport errors, HTTP 429/5xx). A JSON-RPC error object or
        a malformed body is deterministic and is NOT retried. A JSON
        null result is a definitive answer and returns as None."""
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": method,
            "params": params,
        }
        last_error: ChainUnavailable | None = None
        for attempt in range(3):
            if attempt:
                # Backoff matters most on 429: the public Base RPC
                # rate-limits eth_getLogs bursts (measured live
                # 2026-11-22 — a bare retry still drew 429).
                await asyncio.sleep(0.5 if attempt == 1 else 1.5)
            try:
                resp = await self._client.post(self._url, json=payload)
            except httpx.HTTPError as e:
                last_error = ChainUnavailable(f"RPC {method}: transport error: {e}")
                continue
            if resp.status_code != 200:
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_error = ChainUnavailable(f"RPC {method}: HTTP {resp.status_code}")
                    continue
                raise ChainUnavailable(f"RPC {method}: HTTP {resp.status_code}")
            try:
                body = resp.json()
            except ValueError as e:
                raise ChainUnavailable(f"RPC {method}: non-JSON response") from e
            if not isinstance(body, dict) or "error" in body:
                err = body.get("error") if isinstance(body, dict) else body
                raise ChainUnavailable(f"RPC {method}: error: {err}")
            if "result" not in body:
                raise ChainUnavailable(f"RPC {method}: missing result")
            return body["result"]
        assert last_error is not None
        raise last_error

    # --- typed helpers -------------------------------------------------------

    async def block_number(self) -> int:
        return int(await self.call("eth_blockNumber", []), 16)

    async def get_code(self, address: str) -> str:
        result = await self.call("eth_getCode", [address, "latest"])
        if not isinstance(result, str):
            raise ChainUnavailable("RPC eth_getCode: unexpected shape")
        return result

    async def get_storage_at(self, address: str, slot: str) -> str:
        result = await self.call("eth_getStorageAt", [address, slot, "latest"])
        if not isinstance(result, str):
            raise ChainUnavailable("RPC eth_getStorageAt: unexpected shape")
        return result

    async def eth_call(self, to: str, data: str) -> str | None:
        """eth_call result hex, or None when the call reverts / the
        node answers null (e.g. a contract without the method). A
        revert surfaces as a JSON-RPC error — for the read-only
        probes here (owner(), symbol(), allowance()) that is an
        answer ("no such value"), not an upstream failure, so it is
        folded to None instead of raising."""
        try:
            result = await self.call(
                "eth_call", [{"to": to, "data": data}, "latest"]
            )
        except ChainUnavailable:
            return None
        return result if isinstance(result, str) else None

    async def get_logs(self, filter_params: dict) -> list:
        result = await self.call("eth_getLogs", [filter_params])
        if result is None:
            return []
        if not isinstance(result, list):
            raise ChainUnavailable("RPC eth_getLogs: unexpected shape")
        return result

    async def block_timestamp(self, number: int) -> int | None:
        block = await self.call("eth_getBlockByNumber", [hex(number), False])
        if not isinstance(block, dict):
            return None
        ts = block.get("timestamp")
        try:
            return int(ts, 16) if isinstance(ts, str) else None
        except ValueError:
            return None

    async def tx_block_number(self, tx_hash: str) -> int | None:
        tx = await self.call("eth_getTransactionByHash", [tx_hash])
        if not isinstance(tx, dict):
            return None
        num = tx.get("blockNumber")
        try:
            return int(num, 16) if isinstance(num, str) else None
        except ValueError:
            return None


class Blockscout:
    """Blockscout (Base) v2 client — the subset the due-diligence
    routes read (mirrors stall-row app/blockscout.py). Every method
    returns None on any failure; callers mark fields unknown."""

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self._client = client
        self._base = base_url.rstrip("/")

    async def _get_json(self, url: str, params: dict | None = None):
        try:
            resp = await self._client.get(url, params=params, headers=_UA)
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None  # Cloudflare challenge page or other non-JSON

    async def address_info(self, address: str) -> dict | None:
        """{is_contract, name, creation_transaction_hash,
        creation_timestamp} from v2 /addresses/{address}. The
        creation fields are passed through only when the explorer
        actually returns them (names vary across deployments)."""
        body = await self._get_json(f"{self._base}/api/v2/addresses/{address}")
        if not isinstance(body, dict):
            return None
        return {
            "is_contract": body.get("is_contract")
            if isinstance(body.get("is_contract"), bool)
            else None,
            "name": body.get("name") if isinstance(body.get("name"), str) else None,
            "creation_transaction_hash": body.get("creation_transaction_hash")
            if isinstance(body.get("creation_transaction_hash"), str)
            else None,
            "creation_timestamp": body.get("creation_timestamp")
            if isinstance(body.get("creation_timestamp"), str)
            else None,
        }

    async def smart_contract(self, address: str) -> dict | None:
        """{is_verified, name, proxy_type, implementations} from v2
        /smart-contracts/{address}. None when the explorer has no
        smart-contract record (unverified / unknown contract)."""
        body = await self._get_json(
            f"{self._base}/api/v2/smart-contracts/{address}"
        )
        if not isinstance(body, dict):
            return None
        implementations = []
        raw_impls = body.get("implementations")
        if isinstance(raw_impls, list):
            for item in raw_impls:
                if isinstance(item, dict):
                    addr = item.get("address_hash") or item.get("address")
                    if isinstance(addr, str):
                        implementations.append(addr)
        return {
            "is_verified": body.get("is_verified")
            if isinstance(body.get("is_verified"), bool)
            else None,
            "name": body.get("name") if isinstance(body.get("name"), str) else None,
            "proxy_type": body.get("proxy_type")
            if isinstance(body.get("proxy_type"), str)
            else None,
            "implementations": implementations,
        }

    async def token_info(self, address: str) -> dict | None:
        """{symbol, name, decimals} from v2 /tokens/{address}."""
        body = await self._get_json(f"{self._base}/api/v2/tokens/{address}")
        if not isinstance(body, dict):
            return None
        decimals = body.get("decimals")
        try:
            decimals = int(decimals) if decimals is not None else None
        except (TypeError, ValueError):
            decimals = None
        return {
            "symbol": body.get("symbol") if isinstance(body.get("symbol"), str) else None,
            "name": body.get("name") if isinstance(body.get("name"), str) else None,
            "decimals": decimals,
        }
