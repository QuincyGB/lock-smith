"""The Verdict Row Fleet Status link: skill.md and llms.txt name the
fleet-wide status page hosted on StallRow (HTML + JSON twin), rendered
from the standing checker's own state. Hosted on StallRow only; every
stall links it."""

from app.config import load_settings
from app.discovery import llms_txt, skill_md

BASE = "https://stall.example"
STATUS = "https://stall-row-production.up.railway.app/status"
STATUS_JSON = "https://stall-row-production.up.railway.app/status.json"


def test_fleet_status_link_in_skill_and_llms():
    settings = load_settings()
    for doc in (skill_md(settings, BASE), llms_txt(settings, BASE)):
        assert STATUS in doc
        assert STATUS_JSON in doc
