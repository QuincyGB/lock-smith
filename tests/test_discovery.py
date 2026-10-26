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


def test_input_schema_shape():
    assert AUDIT_INPUT_SCHEMA["required"] == ["endpoint_url"]


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
