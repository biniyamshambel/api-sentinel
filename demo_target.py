"""Intentionally under-configured local API used for the graduation demo.

This target exists only to demonstrate findings. It is deliberately missing
several HTTP security headers and must never be deployed publicly.

Run it only on loopback:
    .venv/bin/uvicorn demo_target:app --host 127.0.0.1 --port 8001
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse

app = FastAPI(title="API Sentinel Demo Target", docs_url=None, redoc_url=None)


@app.get("/")
async def root():
    return {"service": "demo-target", "status": "running"}


@app.get("/api/orders")
async def orders():
    # Deliberately missing CSP and Referrer-Policy; includes nosniff to show a pass.
    return JSONResponse(
        content={"orders": [{"id": 1001, "status": "processing"}]},
        headers={"X-Content-Type-Options": "nosniff"},
    )


@app.get("/api/secure")
async def secure():
    return JSONResponse(
        content={"status": "ok"},
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
        },
    )


@app.get("/api/error")
async def error():
    return JSONResponse(status_code=500, content={"error": "simulated upstream failure"})


@app.get("/redirect")
async def redirect():
    return RedirectResponse(url="/api/orders", status_code=302)
