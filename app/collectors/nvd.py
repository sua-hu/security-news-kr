import httpx
import json
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from app.config import NVD_API_URL, NVD_API_KEY
from app import database as db

logger = logging.getLogger(__name__)


def parse_severity(metrics: dict) -> tuple:
    """Extract severity and CVSS score from NVD metrics."""
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            metric = metrics[version][0]
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            return severity.upper(), score
    return "UNKNOWN", 0.0


async def collect_nvd_cves(days: int = 120):
    """Collect recent CVEs from NVD API 2.0 with pagination."""
    logger.info(f"Collecting CVEs from NVD (last {days} days)...")
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    collected = 0
    start_index = 0
    delay = 1.0 if NVD_API_KEY else 6.5

    try:
        async with httpx.AsyncClient(timeout=60) as client:
          while True:
            params = {
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }

            resp = await client.get(NVD_API_URL, params=params, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code}: {resp.text[:200]}")
                break
            data = resp.json()

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                descriptions = cve_data.get("descriptions", [])
                desc_en = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_en = d.get("value", "")
                        break

                metrics = cve_data.get("metrics", {})
                severity, cvss_score = parse_severity(metrics)

                refs = cve_data.get("references", [])
                refs_list = [r.get("url", "") for r in refs[:5]]

                published = cve_data.get("published", "")
                pub_date = None
                if published:
                    try:
                        pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                affected = []
                configs = cve_data.get("configurations", [])
                for config in configs:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            criteria = match.get("criteria", "")
                            if criteria:
                                affected.append(criteria)

                await db.insert_cve(
                    cve_id=cve_id,
                    description=desc_en,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="nvd",
                    affected_products=json.dumps(affected[:10]) if affected else None,
                    references_json=json.dumps(refs_list) if refs_list else None,
                    published_at=pub_date,
                )
                collected += 1

            logger.info(f"NVD: {collected}/{total_results} fetched so far")
            start_index += 2000
            if start_index >= total_results:
                break
            await asyncio.sleep(delay)

        await db.log_collection("nvd", "success", collected)
        logger.info(f"NVD: Collected {collected} CVEs total")

    except Exception as e:
        logger.error(f"NVD collection error (got {collected} so far): {e}")
        await db.log_collection("nvd", "error", collected, str(e))

    return collected
