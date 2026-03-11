from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class Article(BaseModel):
    id: Optional[int] = None
    source: str
    title: str
    title_ko: Optional[str] = None
    summary: Optional[str] = None
    summary_ko: Optional[str] = None
    url: str
    published_at: Optional[datetime] = None
    collected_at: Optional[datetime] = None


class CVE(BaseModel):
    id: Optional[int] = None
    cve_id: str
    description: Optional[str] = None
    description_ko: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    source: str
    affected_products: Optional[str] = None
    references_json: Optional[str] = None
    published_at: Optional[datetime] = None
    is_kev: bool = False
    kev_due_date: Optional[str] = None
    collected_at: Optional[datetime] = None
