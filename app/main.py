import asyncio
import logging
import math
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from pathlib import Path

from app import database as db
from app.config import RSS_FEEDS
from app.scheduler import start_scheduler, stop_scheduler, collect_and_translate, get_scheduler_status

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    logger.info("Database initialized")
    asyncio.create_task(collect_and_translate())
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="Security News KR", lifespan=lifespan)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def parse_json_safe(text):
    if not text:
        return []
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []


templates.env.filters["parse_json"] = parse_json_safe


# --- Exception Handlers ---

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    return HTMLResponse(content=str(exc.detail), status_code=exc.status_code)


# --- Pages ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    articles = await db.get_articles(limit=6)
    cves = await db.get_cves(limit=10, severity="CRITICAL")
    if len(cves) < 10:
        high_cves = await db.get_cves(limit=10 - len(cves), severity="HIGH")
        cves.extend(high_cves)
    kev_cves = await db.get_kev_cves(limit=5)
    stats = await db.get_stats()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "articles": articles,
        "cves": cves,
        "kev_cves": kev_cves,
        "stats": stats,
    })


@app.get("/news", response_class=HTMLResponse)
async def news_list(
    request: Request,
    page: int = Query(1, ge=1),
    source: str = Query(None),
    search: str = Query(None),
):
    per_page = 12
    offset = (page - 1) * per_page
    articles = await db.get_articles(limit=per_page, offset=offset, source=source, search=search)
    total = await db.get_articles_count(source=source, search=search)
    total_pages = math.ceil(total / per_page) if total > 0 else 1

    sources = list(RSS_FEEDS.keys())
    return templates.TemplateResponse("news_list.html", {
        "request": request,
        "articles": articles,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "source": source,
        "search": search or "",
        "sources": sources,
    })


@app.get("/news/{article_id}", response_class=HTMLResponse)
async def news_detail(request: Request, article_id: int):
    article = await db.get_article_by_id(article_id)
    if not article:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    return templates.TemplateResponse("news_detail.html", {
        "request": request,
        "article": article,
    })


@app.get("/cves", response_class=HTMLResponse)
async def cve_list(
    request: Request,
    page: int = Query(1, ge=1),
    severity: str = Query(None),
    search: str = Query(None),
):
    per_page = 20
    offset = (page - 1) * per_page
    cves = await db.get_cves(limit=per_page, offset=offset, severity=severity, search=search)
    total = await db.get_cves_count(severity=severity, search=search)
    total_pages = math.ceil(total / per_page) if total > 0 else 1

    return templates.TemplateResponse("cve_list.html", {
        "request": request,
        "cves": cves,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "severity": severity,
        "search": search or "",
    })


@app.get("/cves/{cve_id}", response_class=HTMLResponse)
async def cve_detail(request: Request, cve_id: str):
    cve = await db.get_cve_by_id(cve_id)
    if not cve:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    return templates.TemplateResponse("cve_detail.html", {
        "request": request,
        "cve": cve,
    })


@app.get("/kev", response_class=HTMLResponse)
async def kev_list(
    request: Request,
    page: int = Query(1, ge=1),
):
    per_page = 20
    offset = (page - 1) * per_page
    cves = await db.get_kev_cves(limit=per_page, offset=offset)
    return templates.TemplateResponse("kev_list.html", {
        "request": request,
        "cves": cves,
        "page": page,
    })


@app.get("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    q: str = Query(""),
):
    articles = []
    cves = []
    if q.strip():
        articles = await db.get_articles(limit=20, search=q)
        cves = await db.get_cves(limit=20, search=q)
    return templates.TemplateResponse("search.html", {
        "request": request,
        "q": q,
        "articles": articles,
        "cves": cves,
    })


# --- API ---

@app.get("/api/stats")
async def api_stats():
    stats = await db.get_stats()
    stats["scheduler"] = get_scheduler_status()
    return stats


_last_collect_time = None


@app.get("/api/collect")
async def api_collect():
    """Manually trigger a collection cycle (rate limited to once per 2 minutes)."""
    global _last_collect_time
    now = datetime.now()
    if _last_collect_time and now - _last_collect_time < timedelta(minutes=2):
        return {"status": "error", "message": "수집은 2분에 한 번만 가능합니다."}
    _last_collect_time = now
    asyncio.create_task(collect_and_translate())
    return {"status": "collection started"}
