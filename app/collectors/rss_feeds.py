import httpx
import feedparser
import logging
import re
from datetime import datetime
from time import mktime
from typing import Optional
from app.config import RSS_FEEDS
from app import database as db

logger = logging.getLogger(__name__)


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


async def collect_rss_feeds():
    """Collect news from all configured RSS feeds."""
    logger.info("Collecting RSS feeds...")
    total = 0

    headers = {"User-Agent": "SecurityNewsKR/1.0 (RSS Reader)"}
    async with httpx.AsyncClient(timeout=15, headers=headers) as client:
        for source_name, feed_url in RSS_FEEDS.items():
            try:
                resp = await client.get(feed_url, follow_redirects=True)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)

                count = 0
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

                    await db.insert_article(
                        source=source_name,
                        title=title,
                        summary=summary,
                        url=link,
                        published_at=pub_date,
                    )
                    count += 1

                total += count
                await db.log_collection(source_name, "success", count)
                logger.info(f"RSS [{source_name}]: Collected {count} articles")

            except Exception as e:
                logger.error(f"RSS [{source_name}] error: {e}")
                await db.log_collection(source_name, "error", 0, str(e))

    return total
