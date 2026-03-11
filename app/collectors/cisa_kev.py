import httpx
import json
import logging
from datetime import datetime, timedelta
from app.config import CISA_KEV_URL
from app import database as db

logger = logging.getLogger(__name__)


async def collect_cisa_kev():
    """Collect ALL CISA Known Exploited Vulnerabilities."""
    logger.info("Collecting CISA KEV data (full catalog)...")
    collected = 0

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(date_added, "%Y-%m-%d")
            except ValueError:
                continue

            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            description = (
                f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}: "
                f"{vuln.get('vulnerabilityName', '')}. "
                f"{vuln.get('shortDescription', '')}"
            )

            due_date = vuln.get("dueDate", "")
            ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
            if ransomware == "Known":
                description += " [Ransomware campaign known]"

            await db.insert_cve(
                cve_id=cve_id,
                description=description,
                severity="CRITICAL",
                cvss_score=None,
                source="cisa_kev",
                affected_products=json.dumps([
                    f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}"
                ]),
                published_at=added_dt,
                is_kev=True,
                kev_due_date=due_date,
            )
            collected += 1

        await db.log_collection("cisa_kev", "success", collected)
        logger.info(f"CISA KEV: Collected {collected} entries")

    except Exception as e:
        logger.error(f"CISA KEV collection error: {e}")
        await db.log_collection("cisa_kev", "error", 0, str(e))

    return collected
