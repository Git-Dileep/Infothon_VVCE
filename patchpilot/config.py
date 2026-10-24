"""Single source of truth for paths, weights and tiers. Keep in sync with config/project.json."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # dotenv is optional
    pass

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.getenv("DB_PATH", str(ROOT / "data" / "fixture.db"))
FIXTURE_PATH = ROOT / "data" / "fixture" / "fixture.json"
NEW_KEV_FIXTURE_PATH = ROOT / "data" / "fixture" / "new_kev.json"
SAMPLE_ASSETS_CSV = ROOT / "data" / "fixture" / "sample_assets.csv"
EVAL_PATH = ROOT / "data" / "eval" / "questions.json"
RAW_DIR = ROOT / "data" / "raw"

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

# Risk = 0.35*CVSS/10 + 0.30*EPSS + 0.20*KEV + 0.15*Asset   (all inputs scaled 0..1)
WEIGHTS = {"cvss": 0.35, "epss": 0.30, "kev": 0.20, "asset": 0.15}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

# (tier, minimum score). KEV-listed is ALWAYS Critical regardless of score.
TIERS = [("Critical", 0.75), ("High", 0.50), ("Medium", 0.25), ("Low", 0.0)]
TIER_ORDER = {name: i for i, (name, _) in enumerate(TIERS)}

# Asset factor when the asset table is empty (no inventory loaded): neutral.
# When an inventory exists, a CVE matching no asset gets 0.0.
NEUTRAL_ASSET = 0.5
