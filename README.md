# LockSmith — security audits for x402 endpoints

**Automated security checks for one x402 endpoint — not a penetration test.**

ListSmith grades a seller's shop window; LockSmith grades their locks.
You supply one paid route's URL. LockSmith runs a battery of eight
non-destructive, **unpaid** probes against it and returns a structured
verdict — `SECURE` / `FINDINGS` / `EXPOSED` — with per-check results
(`pass` / `finding` + severity / `not_tested` with a reason) and a
concrete fix note for every finding.

- **Route:** `POST /v1/audit` — **$0.50 flat** (USDC on Base, x402 v2 exact scheme)
- **Input:** `{"endpoint_url": "https://your-service.example.com/v1/route"}`
- **Pay to:** `0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F`
- **Live:** https://lock-smith-production.up.railway.app

No accounts, no API keys: payment is the authentication. LockSmith
never pays the target — every probe is an unpaid request, so an audit
can never charge the endpoint being audited.

## The battery (exactly these eight checks)

| # | Check | What it does |
|---|-------|--------------|
| 1 | `paywall_present` | An unpaid request must draw HTTP 402 with a parseable x402 challenge. A 200 unpaid is **EXPOSED** (critical). |
| 2 | `challenge_sanity` | The challenge's scheme, network, asset, amount (> 0, integer smallest units), and payTo must be complete and self-consistent. |
| 3 | `garbage_payment` | A request carrying base64-junk payment headers must be rejected (402). A 200 is critical. |
| 4 | `forged_payment` | A structurally valid EIP-3009 `TransferWithAuthorization` payload whose signature was made over *different* terms than the endpoint's own challenge must be rejected. A 200 is critical: the gate is trusting the header's shape. |
| 5 | `exposure_surface` | `/.env`, `/.git/config`, `/debug`, `/metrics`, `/admin` on the target origin must not serve real content (content is judged, not just the status code; a styled 404 is not a hit). |
| 6 | `error_hygiene` | Malformed-JSON and wrong-content-type requests must draw clean errors — no stack traces, file paths, SQL detail, or framework debug pages. |
| 7 | `body_cap` | One single POST with a ~1.1 MiB junk body must be refused (413/400, a paywall 402, or an early connection reset) rather than swallowed (200) or crashed on (5xx). One probe, small scale — a sanity check, not a DoS. |
| 8 | `discovery_consistency` | `/.well-known/x402` / `/openapi.json` must advertise the audited route with accepts matching the live challenge (amount, payTo, network). Charging differently than advertised is a finding. |

Probe discipline: at most ~20 requests per audit, per-probe timeouts,
and LockSmith's own fetching follows the fleet SSRF discipline
(resolve + reject non-public addresses, per-hop redirect re-checks,
capped response bodies). **Auditing a non-public address is refused**
as invalid input (HTTP 422, which never settles a payment).

## Honesty rules

- Target unreachable or probe infrastructure fails → **502, and the
  caller's payment does not settle** (the x402 middleware settles only
  on responses < 400).
- A check that could not run is reported **`not_tested` with a
  reason** — never as a pass.
- The example output in the discovery document is a **real audit**
  this engine ran against the fleet's own Token Verdict route.

## What v1 does NOT check

- Anything requiring a real payment to the target (paid-response
  correctness, settlement behaviour under load, replay of a *valid*
  payment).
- Authorization or business logic behind the paywall.
- Active SSRF testing of the target (whether the *target* can be made
  to fetch internal addresses) — v1 checks the target's surface, not
  its outbound behaviour.
- Forged-payment construction for chains/assets other than USDC on
  Base (reported `not_tested` there, honestly).
- TLS configuration, DNS/email records, dependency CVEs of the target.

## Verdict composition

- Any **high** or **critical** finding → `EXPOSED`
- Any finding of lower severity → `FINDINGS`
- No findings → `SECURE`

## Running it

```bash
pip install -r requirements.txt
python -m app.main            # serves on $PORT (default 3000)
python -m pytest              # test suite (32 tests, fully offline)
```

Configuration is by environment, mirroring the rest of the Verdict Row
fleet: `X402_PAY_TO`, `X402_AUDIT_PRICE_USDC` (default `$0.50`),
`X402_NETWORK` (default `eip155:8453`), `X402_FACILITATOR_URL` (CDP for
Bazaar cataloging, with `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`; PayAI
and keyless facilitators supported the same way), `X402_SERVICE_NAME`,
`LOCKSMITH_FETCH_TIMEOUT_S`.

## Fleet

Fifth service of the Verdict Row fleet, sibling of
[ListSmith](https://github.com/QuincyGB/list-smith) (listing grades &
repairs). The battery is calibrated by the fleet's own 2026-10-25
security audit — LockSmith's first dogfood run audited all four fleet
services and returned SECURE (8/8) on each.
