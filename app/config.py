import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "security_news.db"))
DEEPL_API_KEY = os.getenv("DEEPL_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

DEEPL_API_URL = "https://api-free.deepl.com/v2/translate"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

RSS_FEEDS = {
    "The Hacker News": "https://thehackernews.com/feeds/posts/default",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Threatpost": "https://threatpost.com/feed/",
    "Security Affairs": "https://securityaffairs.com/feed",
    "Graham Cluley": "https://grahamcluley.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "Google Project Zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
}
