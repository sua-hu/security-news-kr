import logging
import time
import asyncio
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.collectors.nvd import collect_nvd_cves
from app.collectors.cisa_kev import collect_cisa_kev
from app.collectors.rss_feeds import collect_rss_feeds
from app.collectors.github_advisory import collect_github_advisories
from app.translator import translate_untranslated_articles, translate_untranslated_cves

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

_last_run_time = None
_last_run_status = None


async def collect_and_translate():
    """Collect from all sources, then translate. Each collector is isolated."""
    global _last_run_time, _last_run_status
    start = time.time()
    logger.info("Starting collection cycle...")
    has_failure = False

    # 1) Fast collectors (RSS, GitHub, CISA KEV)
    collectors = [
        ("RSS", collect_rss_feeds),
        ("GitHub Advisory", collect_github_advisories),
        ("CISA KEV", collect_cisa_kev),
    ]
    for name, collector in collectors:
        try:
            await collector()
        except Exception as e:
            logger.error(f"{name} collector failed: {e}")
            has_failure = True

    # 2) Translation + NVD (slow) in parallel
    try:
        results = await asyncio.gather(
            _translate_all(),
            collect_nvd_cves(),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Parallel task failed: {r}")
                has_failure = True
    except Exception as e:
        logger.error(f"Parallel translate/NVD error: {e}")
        has_failure = True

    elapsed = time.time() - start
    _last_run_time = datetime.now()
    _last_run_status = "partial_failure" if has_failure else "success"
    logger.info(f"Collection cycle complete in {elapsed:.1f}s (status: {_last_run_status})")


async def _translate_all():
    """Run article and CVE translation."""
    try:
        await translate_untranslated_articles(limit=200)
        await translate_untranslated_cves(limit=500)
    except Exception as e:
        logger.error(f"Translation error: {e}")


def get_scheduler_status():
    return {
        "running": scheduler.running,
        "last_run": _last_run_time.isoformat() if _last_run_time else None,
        "last_status": _last_run_status,
    }


def start_scheduler():
    scheduler.add_job(collect_and_translate, "interval", minutes=10, id="collect_all",
                      replace_existing=True, max_instances=1)
    scheduler.start()
    logger.info("Scheduler started")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
