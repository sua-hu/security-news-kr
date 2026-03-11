# Security News KR

글로벌 보안 뉴스와 CVE 취약점 정보를 자동으로 수집하고 한국어로 번역하여 제공하는 웹 애플리케이션입니다.

## 주요 기능

- **보안 뉴스 수집** - 7개 주요 보안 매체(The Hacker News, BleepingComputer, Krebs on Security, SecurityWeek, SANS ISC, US-CERT, Dark Reading)의 RSS 피드를 자동 수집
- **CVE 취약점 수집** - NVD(National Vulnerability Database) 및 GitHub Security Advisory에서 최신 CVE 정보 수집
- **CISA KEV 연동** - CISA Known Exploited Vulnerabilities 카탈로그와 연동하여 실제 악용되고 있는 취약점 표시
- **자동 한국어 번역** - DeepL API(우선) 및 Google Translate(폴백)를 활용한 영문 콘텐츠 자동 번역
- **번역 캐시** - 중복 번역 방지를 위한 해시 기반 번역 캐시
- **자동 스케줄링** - APScheduler를 통한 주기적 수집 및 번역 (RSS 30분, NVD 2시간, CISA KEV 6시간, GitHub Advisory 1시간, 번역 15분)

## 기술 스택

| 구분 | 기술 |
|------|------|
| Backend | Python, FastAPI, Uvicorn |
| Database | SQLite (aiosqlite) |
| Template | Jinja2 |
| HTTP Client | httpx |
| RSS Parser | feedparser |
| Scheduler | APScheduler |
| 번역 | DeepL API, Google Translate |

## 프로젝트 구조

```
security-news-kr/
├── run.py                  # 애플리케이션 진입점 (uvicorn 실행)
├── requirements.txt        # Python 의존성
├── .env.example            # 환경변수 템플릿
├── data/
│   └── security_news.db    # SQLite 데이터베이스
└── app/
    ├── main.py             # FastAPI 앱 및 라우트 정의
    ├── config.py           # 환경변수 및 설정값
    ├── database.py         # DB 스키마 및 CRUD 함수
    ├── models.py           # Pydantic 데이터 모델 (Article, CVE)
    ├── scheduler.py        # 수집/번역 스케줄러
    ├── translator.py       # 번역 모듈 (DeepL + Google)
    ├── collectors/
    │   ├── rss_feeds.py    # RSS 피드 수집기
    │   ├── nvd.py          # NVD CVE 수집기
    │   ├── cisa_kev.py     # CISA KEV 수집기
    │   └── github_advisory.py  # GitHub Advisory 수집기
    └── templates/
        ├── base.html       # 기본 레이아웃
        ├── index.html      # 대시보드 (메인 페이지)
        ├── news_list.html  # 뉴스 목록
        ├── news_detail.html# 뉴스 상세
        ├── cve_list.html   # CVE 목록
        ├── cve_detail.html # CVE 상세
        └── kev_list.html   # KEV 목록
```

## 설치 및 실행

### 1. 의존성 설치

```bash
pip install -r requirements.txt
```

### 2. 환경변수 설정

`.env.example`을 복사하여 `.env` 파일을 생성하고 API 키를 입력합니다.

```bash
cp .env.example .env
```

```env
DEEPL_API_KEY=your_deepl_api_key_here    # 선택 (없으면 Google Translate 사용)
NVD_API_KEY=your_nvd_api_key_here        # 선택 (없으면 rate limit 제한)
GITHUB_TOKEN=your_github_token_here      # 선택 (없으면 rate limit 제한)
DATABASE_PATH=./data/security_news.db    # 기본값 사용 가능
```

### 3. 실행

```bash
python run.py
```

서버가 `http://0.0.0.0:8000`에서 시작되며, 시작 시 자동으로 첫 수집을 실행합니다.

## 웹 페이지

| 경로 | 설명 |
|------|------|
| `/` | 대시보드 - 최신 뉴스, 주요 CVE, KEV 요약 |
| `/news` | 보안 뉴스 목록 (소스별 필터, 페이지네이션) |
| `/news/{id}` | 뉴스 상세 (원문 + 한국어 번역) |
| `/cves` | CVE 목록 (심각도 필터, 검색, 페이지네이션) |
| `/cves/{cve_id}` | CVE 상세 정보 |
| `/kev` | CISA KEV 목록 (실제 악용 취약점) |

## API

| 엔드포인트 | 설명 |
|------------|------|
| `GET /api/stats` | 수집 통계 (뉴스/CVE/KEV 수, 번역 현황) |
| `GET /api/collect` | 수동 수집 트리거 |

## 데이터베이스

SQLite 기반으로 4개 테이블을 사용합니다:

- **articles** - 보안 뉴스 기사 (원문 + 한국어 번역)
- **cves** - CVE 취약점 정보 (CVSS 점수, 심각도, KEV 여부 포함)
- **translation_cache** - 번역 캐시 (MD5 해시 기반 중복 방지)
- **collection_logs** - 수집 이력 로그
