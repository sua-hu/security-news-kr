import httpx
import json
import logging
from datetime import datetime
from app import database as db

logger = logging.getLogger(__name__)

# CISA Vulnrichment - enriched CVE data from CISA's ADP program
VULNRICHMENT_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/index.json"


async def collect_vulnrichment():
    """Collect CISA Vulnrichment enriched CVE data (SSVC decisions, KEV cross-ref)."""
    logger.info("Collecting CISA Vulnrichment data...")
    collected = 0

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(VULNRICHMENT_URL, follow_redirects=True)
            if resp.status_code != 200:
                logger.warning(f"Vulnrichment returned {resp.status_code}")
                await db.log_collection("vulnrichment", "error", 0, f"HTTP {resp.status_code}")
                return 0

            data = resp.json()
            if not isinstance(data, list):
                logger.warning("Vulnrichment: unexpected data format")
                return 0

            cves_batch = []
            for item in data[:500]:
                cve_id = item.get("cveId", "")
                if not cve_id:
                    continue

                description = item.get("description", "")
                ssvc_decision = item.get("ssvcDecision", "")
                if ssvc_decision:
                    description = f"[SSVC: {ssvc_decision}] {description}"

                severity = "UNKNOWN"
                cvss_score = None
                if "cvssScore" in item:
                    cvss_score = item["cvssScore"]
                if "severity" in item:
                    severity = item["severity"].upper()

                pub_date = None
                if "datePublished" in item:
                    try:
                        pub_date = datetime.fromisoformat(item["datePublished"].replace("Z", "+00:00"))
                    except ValueError:
                        pass

                is_kev = item.get("isKev", False)
                affected = json.dumps(item.get("affectedProducts", [])[:10]) if item.get("affectedProducts") else None

                cves_batch.append((
                    cve_id, description, severity, cvss_score, "vulnrichment",
                    affected, None, pub_date, is_kev, None,
                ))

            if cves_batch:
                collected = await db.batch_insert_cves(cves_batch)

        await db.log_collection("vulnrichment", "success", collected)
        logger.info(f"Vulnrichment: Collected {collected} enriched CVEs")

    except Exception as e:
        logger.error(f"Vulnrichment collection error: {e}")
        await db.log_collection("vulnrichment", "error", 0, str(e))

    return collected
