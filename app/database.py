import aiosqlite
import json
from datetime import datetime
from typing import Optional
from app.config import DATABASE_PATH

DB_PATH = DATABASE_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    title_ko TEXT,
    summary TEXT,
    summary_ko TEXT,
    url TEXT UNIQUE NOT NULL,
    published_at TIMESTAMP,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    description_ko TEXT,
    severity TEXT,
    cvss_score REAL,
    source TEXT,
    affected_products TEXT,
    references_json TEXT,
    published_at TIMESTAMP,
    is_kev BOOLEAN DEFAULT 0,
    kev_due_date TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS translation_cache (
    hash TEXT PRIMARY KEY,
    original TEXT NOT NULL,
    translated TEXT NOT NULL,
    char_count INTEGER,
    translated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS collection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    status TEXT,
    items_count INTEGER,
    error_message TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


# --- Articles ---

async def insert_article(source: str, title: str, summary: str, url: str,
                         published_at: Optional[datetime] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                """INSERT OR IGNORE INTO articles (source, title, summary, url, published_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (source, title, summary, url, published_at)
            )
            await db.commit()
        except Exception:
            pass


async def get_articles(limit: int = 20, offset: int = 0, source: Optional[str] = None,
                       search: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []

        if source:
            conditions.append("source = ?")
            params.append(source)
        if search:
            conditions.append(
                "(title LIKE ? OR title_ko LIKE ? OR summary LIKE ? OR summary_ko LIKE ?)"
            )
            params.extend([f"%{search}%"] * 4)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        cursor = await db.execute(
            f"SELECT * FROM articles {where} ORDER BY published_at DESC LIMIT ? OFFSET ?",
            params
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_article_by_id(article_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_articles_count(source: Optional[str] = None, search: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        conditions = []
        params = []
        if source:
            conditions.append("source = ?")
            params.append(source)
        if search:
            conditions.append(
                "(title LIKE ? OR title_ko LIKE ? OR summary LIKE ? OR summary_ko LIKE ?)"
            )
            params.extend([f"%{search}%"] * 4)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        cursor = await db.execute(f"SELECT COUNT(*) FROM articles {where}", params)
        row = await cursor.fetchone()
        return row[0]


async def update_article_translation(article_id: int, title_ko: str, summary_ko: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE articles SET title_ko = ?, summary_ko = ? WHERE id = ?",
            (title_ko, summary_ko, article_id)
        )
        await db.commit()


# --- CVEs ---

async def insert_cve(cve_id: str, description: str, severity: str,
                     cvss_score: Optional[float], source: str,
                     affected_products: Optional[str] = None,
                     references_json: Optional[str] = None,
                     published_at: Optional[datetime] = None,
                     is_kev: bool = False, kev_due_date: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                """INSERT OR IGNORE INTO cves
                   (cve_id, description, severity, cvss_score, source,
                    affected_products, references_json, published_at, is_kev, kev_due_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cve_id, description, severity, cvss_score, source,
                 affected_products, references_json, published_at, is_kev, kev_due_date)
            )
            await db.commit()
        except Exception:
            pass


async def get_cves(limit: int = 20, offset: int = 0, severity: Optional[str] = None,
                   search: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if search:
            conditions.append("(cve_id LIKE ? OR description LIKE ? OR description_ko LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        cursor = await db.execute(
            f"SELECT * FROM cves {where} ORDER BY published_at DESC LIMIT ? OFFSET ?",
            params
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_cve_by_id(cve_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_cves_count(severity: Optional[str] = None, search: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        conditions = []
        params = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if search:
            conditions.append("(cve_id LIKE ? OR description LIKE ? OR description_ko LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        cursor = await db.execute(f"SELECT COUNT(*) FROM cves {where}", params)
        row = await cursor.fetchone()
        return row[0]


async def update_cve_translation(cve_id: str, description_ko: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE cves SET description_ko = ? WHERE cve_id = ?",
            (description_ko, cve_id)
        )
        await db.commit()


async def mark_cve_as_kev(cve_id: str, due_date: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE cves SET is_kev = 1, kev_due_date = ? WHERE cve_id = ?",
            (due_date, cve_id)
        )
        await db.commit()


async def get_kev_cves(limit: int = 20, offset: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM cves WHERE is_kev = 1 ORDER BY published_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_untranslated_articles(limit: int = 50):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM articles
               WHERE title_ko IS NULL OR title_ko = title
               ORDER BY published_at DESC LIMIT ?""",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_untranslated_cves(limit: int = 100):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM cves
               WHERE description IS NOT NULL
                 AND (description_ko IS NULL OR description_ko = description)
               ORDER BY is_kev DESC, published_at DESC LIMIT ?""",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


# --- Translation Cache ---

async def get_cached_translation(text_hash: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT translated FROM translation_cache WHERE hash = ?", (text_hash,)
        )
        row = await cursor.fetchone()
        return row[0] if row else None


async def save_translation_cache(text_hash: str, original: str, translated: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO translation_cache (hash, original, translated, char_count)
               VALUES (?, ?, ?, ?)""",
            (text_hash, original, translated, len(original))
        )
        await db.commit()


# --- Collection Logs ---

async def log_collection(source: str, status: str, items_count: int = 0,
                         error_message: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO collection_logs (source, status, items_count, error_message)
               VALUES (?, ?, ?, ?)""",
            (source, status, items_count, error_message)
        )
        await db.commit()


async def get_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        article_count = (await (await db.execute("SELECT COUNT(*) FROM articles")).fetchone())[0]
        cve_count = (await (await db.execute("SELECT COUNT(*) FROM cves")).fetchone())[0]
        kev_count = (await (await db.execute("SELECT COUNT(*) FROM cves WHERE is_kev = 1")).fetchone())[0]
        translated_articles = (await (await db.execute(
            "SELECT COUNT(*) FROM articles WHERE title_ko IS NOT NULL"
        )).fetchone())[0]
        translated_cves = (await (await db.execute(
            "SELECT COUNT(*) FROM cves WHERE description_ko IS NOT NULL"
        )).fetchone())[0]

        return {
            "articles": article_count,
            "cves": cve_count,
            "kev": kev_count,
            "translated_articles": translated_articles,
            "translated_cves": translated_cves,
        }
