# Security News KR - 프로젝트 분석

## 프로젝트 개요

**Security News KR**은 글로벌 보안 뉴스와 취약점 정보를 자동으로 수집하고 한국어로 번역하여 제공하는 보안 인텔리전스 웹 애플리케이션입니다.

## 핵심 기능

| 기능 | 설명 |
|------|------|
| 다중 소스 수집 | 12개 RSS 피드 + NVD, CISA KEV, GitHub Advisory 3개 API |
| 자동 번역 | DeepL(우선) + Google Translate(폴백), MD5 기반 캐싱 |
| KEV 추적 | 실제 악용되고 있는 취약점 하이라이트 |
| 대시보드 | 통계 카드, 최신 뉴스, 주요 CVE, KEV 목록 |
| 검색 | 뉴스 제목/요약, CVE 설명 전문 검색 |
| 스케줄링 | 10분 간격 자동 수집 (APScheduler) |

## 기술 스택

- **백엔드**: Python + FastAPI 0.115.0, Uvicorn
- **DB**: SQLite (aiosqlite, 비동기)
- **템플릿**: Jinja2 + Tailwind CSS (다크 테마)
- **HTTP 클라이언트**: httpx (비동기)
- **RSS 파싱**: feedparser
- **스케줄러**: APScheduler (AsyncIOScheduler)
- **번역**: DeepL API / Google Translate

## 프로젝트 구조

```
security-news-kr/
├── run.py                    # 진입점 (uvicorn 실행)
├── requirements.txt          # 의존성
├── .env.example              # 환경변수 템플릿
└── app/
    ├── main.py               # FastAPI 앱 & 라우트 (8개 페이지 + 2개 API)
    ├── config.py             # 설정 (API URL, RSS 피드 목록)
    ├── database.py           # SQLite 스키마 & CRUD (4개 테이블)
    ├── models.py             # Pydantic 모델
    ├── scheduler.py          # 10분 간격 수집 스케줄러
    ├── translator.py         # 이중 번역 전략 + 캐싱
    ├── collectors/
    │   ├── rss_feeds.py      # 12개 보안 뉴스 RSS 수집
    │   ├── nvd.py            # NVD API 2.0 CVE 수집
    │   ├── cisa_kev.py       # CISA 악용 취약점 수집
    │   └── github_advisory.py # GitHub 보안 권고 수집
    └── templates/            # Jinja2 HTML 템플릿 (9개)
```

## DB 스키마

4개 테이블로 구성:

- **articles** — 보안 뉴스 (원문 + 한국어 번역)
- **cves** — 취약점 (CVSS 점수, 심각도, KEV 여부)
- **translation_cache** — MD5 기반 번역 캐시
- **collection_logs** — 수집 이력

## 수집 및 스케줄링 흐름

1. 서버 시작 → DB 초기화 → 즉시 첫 수집 실행
2. 10분 간격: RSS → GitHub → CISA KEV → (NVD + 번역 병렬 실행)
3. 수동 트리거: `/api/collect` 엔드포인트 (2분 제한)
4. 동시성 제어: 번역 API 최대 3개 동시 요청 (세마포어)

## 아키텍처 특징

- **완전 비동기**: FastAPI + httpx + aiosqlite로 높은 동시성
- **에러 격리**: 개별 수집기 실패가 전체 앱에 영향 없음
- **속도 제한 준수**: NVD API 키 유무에 따른 요청 간격 조절
- **번역 최적화**: 캐싱으로 중복 API 호출 방지, 배치 처리 (기사 200건, CVE 500건)

## 개선 제안

- Docker 컨테이너화
- CI/CD 파이프라인 구축
- PostgreSQL 전환 (확장성)
- 테스트 코드 추가
