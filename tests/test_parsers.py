"""format_price rendering, including sub-cent precision."""

from app.parsers import format_price

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def test_format_price_known_and_unknown_assets():
    assert format_price("20000", "eip155:8453", USDC) == "$0.02"
    assert format_price("50000", "eip155:8453", USDC) == "$0.05"
    assert format_price("20000", "eip155:8453", "0x0000000000000000000000000000000000000001") is None
    assert format_price(None, "eip155:8453", USDC) is None
    assert format_price("not-a-number", "eip155:8453", USDC) is None


def test_format_price_preserves_sub_cent_precision():
    # Regression (aicom review, 2026-10-29): a $0.001 endpoint rendered
    # price_usdc "$0.00" while amount_units correctly said "1000".
    assert format_price("1000", "eip155:8453", USDC) == "$0.001"
    assert format_price("5000", "eip155:8453", USDC) == "$0.005"
    assert format_price("1", "eip155:8453", USDC) == "$0.000001"
    assert format_price("10000", "eip155:8453", USDC) == "$0.01"
    assert format_price("500000", "eip155:8453", USDC) == "$0.50"
    assert format_price("1000000", "eip155:8453", USDC) == "$1.00"
    assert format_price("0", "eip155:8453", USDC) == "$0.00"
