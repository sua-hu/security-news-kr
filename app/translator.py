import hashlib
import httpx
import logging
import asyncio
import json
from typing import List, Optional, Tuple
from app.config import DEEPL_API_KEY, DEEPL_API_URL
from app import database as db

logger = logging.getLogger(__name__)

GOOGLE_TRANSLATE_URL = "https://translate.googleapis.com/translate_a/single"


def text_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


async def _translate_deepl(client: httpx.AsyncClient, text: str) -> Optional[str]:
    """Translate using DeepL Free API."""
    try:
        resp = await client.post(
            DEEPL_API_URL,
            headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
            json={"text": [text], "source_lang": "EN", "target_lang": "KO"},
        )
        resp.raise_for_status()
        return resp.json()["translations"][0]["text"]
    except Exception as e:
        logger.warning(f"DeepL failed: {e}")
        return None


async def _translate_google(client: httpx.AsyncClient, text: str) -> Optional[str]:
    """Translate using Google Translate (free, no key required)."""
    truncated = text[:4500]
    try:
        resp = await client.get(
            GOOGLE_TRANSLATE_URL,
            params={
                "client": "gtx",
                "sl": "en",
                "tl": "ko",
                "dt": "t",
                "q": truncated,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        # Response format: [[["translated","original",...],...]...]
        if data and data[0]:
            parts = [segment[0] for segment in data[0] if segment and segment[0]]
            translated = "".join(parts)
            if translated and translated != truncated:
                return translated
        return None
    except Exception as e:
        logger.warning(f"Google Translate failed: {e}")
        return None


async def translate_text(text: str, client: Optional[httpx.AsyncClient] = None) -> Tuple[str, bool]:
    """Translate English to Korean. Returns (translated_text, used_api).

    used_api is False if the result came from cache (no API call made).
    """
    if not text or not text.strip():
        return text, False

    # Check cache
    h = text_hash(text)
    cached = await db.get_cached_translation(h)
    if cached:
        return cached, False

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=15)

    try:
        translated = None

        # Try DeepL if configured
        if DEEPL_API_KEY:
            translated = await _translate_deepl(client, text)

        # Fallback to Google Translate (free, no key)
        if not translated:
            translated = await _translate_google(client, text)

        if translated and translated != text:
            await db.save_translation_cache(h, text, translated)
            return translated, True
    finally:
        if own_client:
            await client.aclose()

    return text, True


async def translate_untranslated_articles(limit: int = 200):
    """Translate articles that don't have Korean translations yet."""
    articles = await db.get_untranslated_articles(limit=limit)
    count = 0
    async with httpx.AsyncClient(timeout=15) as client:
        for article in articles:
            title_ko, used_api_1 = await translate_text(article["title"], client)
            summary_ko = ""
            used_api_2 = False
            if article.get("summary"):
                summary_ko, used_api_2 = await translate_text(article["summary"], client)

            if title_ko != article["title"] or (summary_ko and summary_ko != article.get("summary")):
                await db.update_article_translation(article["id"], title_ko, summary_ko)
                count += 1

            if used_api_1 or used_api_2:
                await asyncio.sleep(0.2)

    logger.info(f"Translated {count} articles")
    return count


async def translate_untranslated_cves(limit: int = 500):
    """Translate CVEs that don't have Korean translations yet. KEV entries are prioritized."""
    cves = await db.get_untranslated_cves(limit=limit)
    count = 0
    errors = 0
    async with httpx.AsyncClient(timeout=15) as client:
        for cve in cves:
            desc_ko, used_api = await translate_text(cve["description"], client)
            if desc_ko != cve["description"]:
                await db.update_cve_translation(cve["cve_id"], desc_ko)
                count += 1
            else:
                errors += 1
                if errors > 10:
                    logger.warning("Too many translation failures, stopping early")
                    break

            if used_api:
                await asyncio.sleep(0.2)

    logger.info(f"Translated {count} CVEs")
    return count
