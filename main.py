"""API Sentinel - application entry point.

Run locally with:
    .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import APP_NAME, VERSION, Settings
from app.demo import build_demo_report
from app.errors import ScanInputError
from app.models import HealthResponse, ScanReport, ScanRequest
from app.network import SafeFetcher
from app.scanner import build_report

logger = logging.getLogger("api_sentinel")
logging.basicConfig(
    level=os.getenv("API_SENTINEL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description=(
        "Authorized API health monitoring and a basic HTTP security-configuration "
        "scanner. Intended for public endpoints that you own or have permission to test."
    ),
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def get_settings() -> Settings:
    return Settings.from_env()


def get_fetcher() -> SafeFetcher:
    return SafeFetcher(settings=get_settings())


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'",
    )
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(ScanInputError)
async def scan_input_error_handler(_request: Request, exc: ScanInputError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": exc.message, "code": exc.code},
    )


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=APP_NAME,
        version=VERSION,
        utc_time=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        ssrf_protection="enabled",
        loopback_scanning=settings.loopback_mode,
    )


@app.get("/api/demo", response_model=ScanReport, tags=["scan"])
async def demo(settings: Settings = Depends(get_settings)) -> ScanReport:
    """Return a predictable sample report. No outbound request is performed."""
    return build_demo_report(settings)


@app.post("/api/scan", response_model=ScanReport, tags=["scan"])
async def scan(payload: ScanRequest, fetcher: SafeFetcher = Depends(get_fetcher)) -> ScanReport:
    """Assess a public HTTP(S) API. Input rejections return HTTP 422."""
    fetch = await fetcher.fetch(payload.url)
    return build_report(fetch, fetcher.settings)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=int(os.getenv("API_SENTINEL_PORT", "8000")),
        reload=False,
        log_level=os.getenv("API_SENTINEL_LOG_LEVEL", "info").lower(),
    )
