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
    # --- Major Security News ---
    "The Hacker News": "https://thehackernews.com/feeds/posts/default",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Threatpost": "https://threatpost.com/feed/",
    "Security Affairs": "https://securityaffairs.com/feed",
    "SC Magazine": "https://www.scmagazine.com/feed",
    "Infosecurity Magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "CSO Online": "https://www.csoonline.com/feed/",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",
    "CyberScoop": "https://cyberscoop.com/feed/",
    "The Record": "https://therecord.media/feed",
    # --- Vulnerability Research & Exploits ---
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",
    "Packet Storm": "https://packetstormsecurity.com/feeds/",
    "Rapid7 Blog": "https://blog.rapid7.com/rss/",
    "Zero Day Initiative": "https://www.zerodayinitiative.com/rss/published/",
    "Google Project Zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    # --- Vendor Security Blogs ---
    "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
    "Microsoft Security": "https://www.microsoft.com/en-us/security/blog/feed/",
    "Google TAG": "https://blog.google/threat-analysis-group/rss/",
    "Mandiant Blog": "https://www.mandiant.com/resources/blog/rss.xml",
    "SentinelOne": "https://www.sentinelone.com/blog/feed/",
    "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
    "Palo Alto Unit42": "https://unit42.paloaltonetworks.com/feed/",
    "Sophos News": "https://news.sophos.com/en-us/feed/",
    "ESET Research": "https://www.welivesecurity.com/en/rss/feed/",
    "Trend Micro": "https://www.trendmicro.com/en_us/research.rss.html",
    "Qualys Blog": "https://blog.qualys.com/feed",
    # --- Government & CERT ---
    "US-CERT": "https://www.cisa.gov/news.xml",
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    # --- Expert Blogs ---
    "Graham Cluley": "https://grahamcluley.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "Daniel Miessler": "https://danielmiessler.com/feed/",
    "Naked Security (Sophos)": "https://nakedsecurity.sophos.com/feed/",
    # --- Threat Intelligence ---
    "AlienVault OTX": "https://otx.alienvault.com/pulse/rss",
    "Recorded Future": "https://www.recordedfuture.com/feed",
    "Securelist (Kaspersky)": "https://securelist.com/feed/",
}
