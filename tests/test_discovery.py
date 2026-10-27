"""Discovery consistency: the manifest mirrors the live challenge, the
descriptions stay under the 500-char CDP limit and carry the honest
scope phrase, the shipped example validates against the shipped
output schema, and skill.md lists exactly the eight checks.
"""

import jsonschema
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.config import load_settings
from app.discovery import (
    AUDIT_INPUT_SCHEMA,
    AUDIT_OUTPUT_EXAMPLE,
    AUDIT_OUTPUT_SCHEMA,
    llms_txt,
    skill_md,
    x402_manifest,
)

BASE = "https://lock-smith-production.up.railway.app"
OWNER = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"


@pytest.fixture(scope="module")
def settings():
    return load_settings()


def test_manifest_mirrors_challenge_terms(settings):
    manifest = x402_manifest(settings, BASE)
    assert manifest["payTo"] == OWNER
    (resource,) = [r for r in manifest["resources"] if r["resource"].endswith("/v1/audit")]
    assert resource["price"] == "$0.50"
    (accept,) = resource["accepts"]
    assert accept["amount"] == "500000"
    assert accept["payTo"] == OWNER
    assert accept["network"] == "eip155:8453"
    assert accept["asset"] == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def test_descriptions_honest_and_under_500(settings):
    manifest = x402_manifest(settings, BASE)
    assert "not a penetration test" in manifest["description"]
    assert len(manifest["description"]) <= 500
    (resource,) = [r for r in manifest["resources"] if r["resource"].endswith("/v1/audit")]
    assert "not a penetration test" in resource["description"]
    assert len(resource["description"]) <= 500
    assert len(main.AUDIT_DESCRIPTION) <= 500
    assert "not a penetration test" in main.AUDIT_DESCRIPTION


def test_example_is_real_and_validates():
    # The example is a real audit output; it must satisfy the schema
    # the discovery document publishes for it.
    jsonschema.validate(AUDIT_OUTPUT_EXAMPLE, AUDIT_OUTPUT_SCHEMA)
    assert AUDIT_OUTPUT_EXAMPLE["service"] == "lock-smith"
    assert len(AUDIT_OUTPUT_EXAMPLE["checks"]) == 8
    ids = [c["id"] for c in AUDIT_OUTPUT_EXAMPLE["checks"]]
    assert ids == [
        "paywall_present", "challenge_sanity", "garbage_payment", "forged_payment",
        "exposure_surface", "error_hygiene", "body_cap", "discovery_consistency",
    ]


def test_compact_example_under_settled_sample_limit():
    """Settled's extractor silently drops published output samples over
    ~1.5 KB serialized (measured 2026-10-25: RouteVerdict's 1,453 B
    sample kept and graded as_advertised; Token Verdict's 1,721 B and
    ListSmith's 4,972 B samples dropped -> nothing_to_compare). The
    honest full-mode example is 2,072 B, so the listing publishes the
    compact pair (mode="compact"); the fleet pin is <=1,450 B."""
    import json

    from app.discovery import AUDIT_COMPACT_OUTPUT_EXAMPLE

    assert len(json.dumps(AUDIT_COMPACT_OUTPUT_EXAMPLE).encode()) <= 1450


def test_compact_example_is_compactified_full_example():
    # The published compact example is not hand-maintained prose: it is
    # the engine's compactify() applied to the real full example, so
    # the two can never drift apart; the audit DATA is identical.
    from app.audit import compactify
    from app.discovery import AUDIT_COMPACT_OUTPUT_EXAMPLE

    assert AUDIT_COMPACT_OUTPUT_EXAMPLE == compactify(AUDIT_OUTPUT_EXAMPLE)
    jsonschema.validate(AUDIT_COMPACT_OUTPUT_EXAMPLE, AUDIT_OUTPUT_SCHEMA)
    for key in ("service", "target", "verdict", "summary", "terms_observed", "probes_used"):
        assert AUDIT_COMPACT_OUTPUT_EXAMPLE[key] == AUDIT_OUTPUT_EXAMPLE[key]
    assert AUDIT_COMPACT_OUTPUT_EXAMPLE["mode"] == "compact"
    assert [c["status"] for c in AUDIT_COMPACT_OUTPUT_EXAMPLE["checks"]] == \
        [c["status"] for c in AUDIT_OUTPUT_EXAMPLE["checks"]]


def test_extension_publishes_compact_pair():
    from app.discovery import (
        AUDIT_COMPACT_INPUT_EXAMPLE,
        AUDIT_COMPACT_OUTPUT_EXAMPLE,
        audit_extension,
    )

    ext = audit_extension()
    assert ext["info"]["input"]["body"] == AUDIT_COMPACT_INPUT_EXAMPLE
    assert ext["info"]["output"]["example"] == AUDIT_COMPACT_OUTPUT_EXAMPLE
    assert AUDIT_COMPACT_INPUT_EXAMPLE["mode"] == "compact"


def test_input_schema_shape():
    assert AUDIT_INPUT_SCHEMA["required"] == ["endpoint_url"]
    assert AUDIT_INPUT_SCHEMA["properties"]["mode"]["enum"] == ["full", "compact"]


def test_skill_md_lists_exactly_the_eight_checks(settings):
    text = skill_md(settings, BASE)
    for name in (
        "paywall_present", "challenge_sanity", "garbage_payment", "forged_payment",
        "exposure_surface", "error_hygiene", "body_cap", "discovery_consistency",
    ):
        assert name in text
    assert "not a penetration" in text


def test_llms_txt(settings):
    text = llms_txt(settings, BASE)
    assert "/v1/audit" in text
    assert "$0.50" in text


def test_openapi_carries_discovery_keys():
    client = TestClient(main.app, raise_server_exceptions=False)
    schema = client.get("/openapi.json").json()
    assert "x-discovery" in schema
    assert "/v1/audit" in schema["paths"]
