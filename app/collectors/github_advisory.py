import httpx
import json
import logging
import asyncio
from datetime import datetime
from app.config import GITHUB_ADVISORY_URL, GITHUB_TOKEN
from app import database as db

logger = logging.getLogger(__name__)


async def collect_github_advisories(per_page: int = 100, max_pages: int = 5):
    """Collect security advisories from GitHub Advisory Database with pagination."""
    logger.info("Collecting GitHub Advisories...")
    collected = 0

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    try:
      async with httpx.AsyncClient(timeout=30) as client:
        for page_num in range(1, max_pages + 1):
            params = {
                "per_page": per_page,
                "sort": "updated",
                "direction": "desc",
                "page": page_num,
            }

            resp = await client.get(GITHUB_ADVISORY_URL, headers=headers, params=params)
            resp.raise_for_status()
            advisories = resp.json()

            if not advisories:
                break

            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id") or ghsa_id
                if not cve_id:
                    continue

                summary = adv.get("summary", "")
                description = adv.get("description", "")
                if description:
                    desc_text = f"{summary}. {description[:300]}"
                else:
                    desc_text = summary

                severity = (adv.get("severity") or "UNKNOWN").upper()
                cvss_score = None
                cvss = adv.get("cvss", {})
                if cvss:
                    cvss_score = cvss.get("score")

                published = adv.get("published_at", "")
                pub_date = None
                if published:
                    try:
                        pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                vulns = adv.get("vulnerabilities", [])
                affected = []
                for v in vulns[:5]:
                    pkg = v.get("package", {})
                    name = pkg.get("name", "")
                    ecosystem = pkg.get("ecosystem", "")
                    if name:
                        affected.append(f"{ecosystem}/{name}")

                raw_refs = adv.get("references", [])[:5]
                refs = [r if isinstance(r, str) else r.get("url", "") for r in raw_refs]

                await db.insert_cve(
                    cve_id=cve_id,
                    description=desc_text,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="github",
                    affected_products=json.dumps(affected) if affected else None,
                    references_json=json.dumps(refs) if refs else None,
                    published_at=pub_date,
                )
                collected += 1

            logger.info(f"GitHub Advisory: Page {page_num}, {collected} so far")
            if len(advisories) < per_page:
                break
            await asyncio.sleep(1)

      await db.log_collection("github_advisory", "success", collected)
      logger.info(f"GitHub Advisory: Collected {collected} advisories total")

    except Exception as e:
        logger.error(f"GitHub Advisory collection error: {e}")
        await db.log_collection("github_advisory", "error", collected, str(e))

    return collected
