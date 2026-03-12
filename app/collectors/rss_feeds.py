import httpx
import feedparser
import logging
import re
import asyncio
from datetime import datetime
from time import mktime
from typing import Optional
from app.config import RSS_FEEDS
from app import database as db

logger = logging.getLogger(__name__)

# Concurrency limit per batch to avoid overwhelming targets
_CONCURRENT_FEEDS = 10


def clean_html(text: str) -> str:
    """Remove HTML tags from text."""
    clean = re.sub(r"<[^>]+>", "", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:500]


def parse_date(entry) -> Optional[datetime]:
    """Parse publication date from RSS entry."""
    for attr in ["published_parsed", "updated_parsed"]:
        parsed = getattr(entry, attr, None)
        if parsed:
            try:
                return datetime.fromtimestamp(mktime(parsed))
            except (ValueError, OverflowError):
                pass
    return None


async def _collect_single_feed(client: httpx.AsyncClient, source_name: str, feed_url: str, semaphore: asyncio.Semaphore):
    """Collect articles from a single RSS feed."""
    async with semaphore:
        try:
            resp = await client.get(feed_url, follow_redirects=True, timeout=15)
            feed = feedparser.parse(resp.text)

            articles = []
            for entry in feed.entries[:50]:
                title = entry.get("title", "").strip()
                link = entry.get("link", "").strip()
                if not title or not link:
                    continue

                summary = ""
                if hasattr(entry, "summary"):
                    summary = clean_html(entry.summary)
                elif hasattr(entry, "description"):
                    summary = clean_html(entry.description)

                pub_date = parse_date(entry)
                articles.append((source_name, title, summary, link, pub_date))

            if articles:
                count = await db.batch_insert_articles(articles)
            else:
                count = 0

            await db.log_collection(source_name, "success", count)
            logger.info(f"RSS [{source_name}]: Collected {count} articles")
            return count

        except Exception as e:
            logger.error(f"RSS [{source_name}] error: {e}")
            await db.log_collection(source_name, "error", 0, str(e))
            return 0


async def collect_rss_feeds():
    """Collect news from all configured RSS feeds concurrently."""
    logger.info(f"Collecting {len(RSS_FEEDS)} RSS feeds concurrently...")

    semaphore = asyncio.Semaphore(_CONCURRENT_FEEDS)
    headers = {"User-Agent": "SecurityNewsKR/1.0 (RSS Reader)"}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        tasks = [
            _collect_single_feed(client, name, url, semaphore)
            for name, url in RSS_FEEDS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    total = sum(r for r in results if isinstance(r, int))
    errors = sum(1 for r in results if isinstance(r, Exception))
    if errors:
        logger.warning(f"RSS: {errors} feeds had errors")
    logger.info(f"RSS: Total {total} articles from {len(RSS_FEEDS)} feeds")
    return total
