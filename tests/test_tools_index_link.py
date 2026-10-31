"""The Verdict Row Tools Index link: skill.md and llms.txt name the
fleet-wide index hosted on StallRow (HTML + machine-readable JSON).
The index is hosted on StallRow only; every stall links it."""

from app.config import load_settings
from app.discovery import llms_txt, skill_md

BASE = "https://stall.example"
TOOLS = "https://stall-row-production.up.railway.app/tools"
TOOLS_JSON = "https://stall-row-production.up.railway.app/tools.json"


def test_tools_index_link_in_skill_and_llms():
    settings = load_settings()
    for doc in (skill_md(settings, BASE), llms_txt(settings, BASE)):
        assert TOOLS in doc
        assert TOOLS_JSON in doc
