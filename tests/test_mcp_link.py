"""The MCP manifest link: discovery surfaces name the stall's MCP
server honestly — the stdio wrapper's GitHub repo and its server.json
manifest (source-only; no hosted MCP endpoint is claimed)."""

from app.config import load_settings
from app.discovery import MCP_SERVER, agent_card, llms_txt, skill_md, x402_manifest

BASE = "https://stall.example"
REPO = "https://github.com/QuincyGB/lock-smith-mcp"
MANIFEST = "https://github.com/QuincyGB/lock-smith-mcp/blob/main/server.json"


def test_mcp_link_present_on_all_surfaces():
    assert MCP_SERVER["repository"] == REPO
    assert MCP_SERVER["manifest"] == MANIFEST
    assert MCP_SERVER["transport"] == "stdio"
    settings = load_settings()
    manifest = x402_manifest(settings, BASE)
    assert manifest["extensions"]["mcp"]["repository"] == REPO
    card = agent_card(settings, BASE)
    assert card["mcp"]["manifest"] == MANIFEST
    for doc in (skill_md(settings, BASE), llms_txt(settings, BASE)):
        assert REPO in doc and MANIFEST in doc
