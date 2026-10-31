"""The Inspector Quickstart Pack link: discovery surfaces name the
pack's canonical pages on StallRow (curl / Python / TypeScript) —
the pages are hosted on StallRow only; every stall links them."""

from app.config import load_settings
from app.discovery import QUICKSTART, agent_card, llms_txt, skill_md, x402_manifest

BASE = "https://stall.example"
CURL = "https://stall-row-production.up.railway.app/quickstart/curl"
PYTHON = "https://stall-row-production.up.railway.app/quickstart/python"
TYPESCRIPT = "https://stall-row-production.up.railway.app/quickstart/typescript"


def test_quickstart_link_present_on_all_surfaces():
    assert QUICKSTART["curl"] == CURL
    assert QUICKSTART["python"] == PYTHON
    assert QUICKSTART["typescript"] == TYPESCRIPT
    settings = load_settings()
    manifest = x402_manifest(settings, BASE)
    assert manifest["extensions"]["quickstart"]["curl"] == CURL
    card = agent_card(settings, BASE)
    assert card["quickstart"]["typescript"] == TYPESCRIPT
    for doc in (skill_md(settings, BASE), llms_txt(settings, BASE)):
        assert CURL in doc and PYTHON in doc and TYPESCRIPT in doc
