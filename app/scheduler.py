import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.collectors.nvd import collect_nvd_cves
from app.collectors.cisa_kev import collect_cisa_kev
from app.collectors.rss_feeds import collect_rss_feeds
from app.collectors.github_advisory import collect_github_advisories
from app.translator import translate_untranslated_articles, translate_untranslated_cves

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def collect_and_translate():
    """Collect from fast sources, then translate and NVD in parallel."""
    logger.info("Starting collection cycle...")

    # 1) Fast collectors first (RSS, GitHub, CISA KEV)
    try:
        results = await asyncio.gather(
            collect_rss_feeds(),
            collect_github_advisories(),
            return_exceptions=True,
        )
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.error(f"Fast collector {i} failed: {r}")
        await collect_cisa_kev()
    except Exception as e:
        logger.error(f"Fast collection error: {e}")

    # 2) Translation + NVD (slow) in parallel
    try:
        await asyncio.gather(
            _translate_all(),
            collect_nvd_cves(),
            return_exceptions=True,
        )
    except Exception as e:
        logger.error(f"Parallel translate/NVD error: {e}")

    logger.info("Collection cycle complete")


async def _translate_all():
    """Run article and CVE translation."""
    try:
        await translate_untranslated_articles(limit=200)
        await translate_untranslated_cves(limit=500)
    except Exception as e:
        logger.error(f"Translation error: {e}")


def start_scheduler():
    """Configure and start the scheduler."""
    # Full collection + translation: every 10 minutes
    scheduler.add_job(collect_and_translate, "interval", minutes=10, id="collect_all",
                      replace_existing=True, max_instances=1)

    scheduler.start()
    logger.info("Scheduler started")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
