"""The Verdict Row Public Changelog link: skill.md and llms.txt name
the fleet-wide changelog feed hosted on StallRow (Atom + JSON twin).
The feed is hosted on StallRow only; every stall links it."""

from app.config import load_settings
from app.discovery import llms_txt, skill_md

BASE = "https://stall.example"
ATOM = "https://stall-row-production.up.railway.app/changelog.atom"
JSON_URL = "https://stall-row-production.up.railway.app/changelog.json"


def test_changelog_link_in_skill_and_llms():
    settings = load_settings()
    for doc in (skill_md(settings, BASE), llms_txt(settings, BASE)):
        assert ATOM in doc
        assert JSON_URL in doc
