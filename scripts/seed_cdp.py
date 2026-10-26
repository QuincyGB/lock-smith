"""seed_cdp.py — ONE paid $0.50 seed call to the deployed LockSmith.

Purpose: the first settled payment through the CDP facilitator is what
catalogs the route in the CDP Bazaar. The seed audits the fleet's own
Token Verdict route — the demo pairing (LockSmith's discovery example
is a real audit of that same target).

Reuses verdict-loop's proven x402 client (~/workspace/verdict-loop)
field-for-field; the signer is the agent wallet at ~/.evm-wallet/key
(read by the client loader, never printed here).

Usage:
    python scripts/seed_cdp.py [lock_smith_base_url] [output_json]

    lock_smith_base_url defaults to
    https://lock-smith-production.up.railway.app
    output_json defaults to /tmp/locksmith_seed_result.json

Safety: refuses to pay anything other than exactly 500000 units
($0.50); aborts if the outcome is not a settled "paid" call.
"""

from __future__ import annotations

import json
import os
import sys

# Bracketed no_proxy entries crash httpx client construction (fleet fix).
for _var in ("no_proxy", "NO_PROXY"):
    _val = os.environ.get(_var)
    if _val:
        os.environ[_var] = ",".join(e for e in _val.split(",") if "[" not in e and "]" not in e)

sys.path.insert(0, os.path.expanduser("~/workspace/verdict-loop"))

import httpx  # noqa: E402

from verdict_loop.x402 import call_paid_endpoint, load_account_from_env  # noqa: E402

DEFAULT_BASE = "https://lock-smith-production.up.railway.app"
TARGET = "https://token-verdict-production.up.railway.app/v1/verdict"
EXPECTED_UNITS = 500000


def main() -> int:
    base = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE).rstrip("/")
    out_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/locksmith_seed_result.json"

    account = load_account_from_env(
        {"AGENT_KEY_FILE": os.path.expanduser("~/.evm-wallet/key")}
    )
    if account is None:
        print("no signer — agent wallet key not loadable; aborting", file=sys.stderr)
        return 1
    print(f"buyer (agent wallet): {account.address}")

    with httpx.Client(timeout=180.0) as http:
        outcome = call_paid_endpoint(
            http,
            f"{base}/v1/audit",
            {"endpoint_url": TARGET},
            account=account,
        )

    print(f"mode: {outcome.mode}  price_units: {outcome.price_units}")
    if outcome.mode != "paid" or outcome.price_units != EXPECTED_UNITS:
        print(f"ABORT: expected a settled paid call at {EXPECTED_UNITS} units; note: {outcome.note}", file=sys.stderr)
        return 1

    receipt = outcome.receipt or {}
    print(f"receipt: {json.dumps(receipt)[:400]}")
    result = outcome.response or {}
    print(f"audit verdict: {result.get('verdict')}  summary: {result.get('summary')}")
    with open(out_path, "w") as f:
        json.dump({"receipt": receipt, "response": result}, f, indent=2)
    print(f"full result saved to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
