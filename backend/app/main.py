"""TRACE-X FastAPI application.

Run locally:  uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import api_router
from .api.accounts import PUBLIC_PATHS as AUTH_PUBLIC_PATHS
from .config import API_PREFIX, APP_ENV, ENGINE_VERSION, RULES_VERSION, ensure_directories
from .db import SessionLocal, init_db

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s :: %(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("tracex")


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_directories()
    init_db()
    logger.info("TRACE-X engine %s (ruleset %s) ready; env=%s", ENGINE_VERSION, RULES_VERSION,
                APP_ENV)
    yield


app = FastAPI(
    title="TRACE-X",
    description=(
        "Explainable digital forensics engine: timeline reconstruction, cross-artifact "
        "correlation, anti-forensics detection, suspicion chains, uncertainty-aware reasoning "
        "and reproducible investigation reports."
    ),
    version=ENGINE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def user_auth_guard(request: Request, call_next):
    """Enforce user sessions when TRACEX_USER_AUTH_ENABLED is active.

    Every API request must present a live bearer session except the public
    auth endpoints (status/signup/login), health/version metadata and the
    docs.  A valid session is resolved once here and exposed as
    `request.state.user`, which `current_actor` turns into the audit actor
    and investigation owner.  API-key mode (TRACEX_AUTH_ENABLED) keeps
    working unchanged: when only API keys are configured this guard passes
    every request through.
    """
    from . import config
    from .auth import _match_api_key, _extract_token
    from .services.accounts import resolve_session

    path = request.url.path
    api = API_PREFIX.rstrip("/")
    if (not config.USER_AUTH_ENABLED or request.method == "OPTIONS"
            or not path.startswith(api + "/")
            or path[len(api):] in AUTH_PUBLIC_PATHS
            or path[len(api):].split("?")[0] in {"/health", "/version", "/openapi.json"}):
        return await call_next(request)

    token = _extract_token(request)
    user = None
    if token:
        db = SessionLocal()
        try:
            user = resolve_session(db, token)
        finally:
            db.close()
    if user is None:
        # API-key mode stays usable for scripts alongside session sign-in:
        # a valid key passes the guard; current_actor still validates it.
        if config.AUTH_ENABLED and token and _match_api_key(token):
            return await call_next(request)
        return JSONResponse(status_code=401, content={"detail": {
            "code": "auth_required",
            "message": "your session has expired or is invalid — sign in again"}})
    request.state.user = user
    return await call_next(request)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - started) * 1000
    if not request.url.path.endswith(("/activity", "/events")):
        logger.info("%s %s -> %s (%.1f ms)", request.method, request.url.path,
                    response.status_code, duration_ms)
    response.headers["X-TRACE-X-Engine"] = ENGINE_VERSION
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "request failed schema validation",
                "details": [
                    {"field": ".".join(str(p) for p in err.get("loc", [])),
                     "issue": err.get("type"), "message": err.get("msg")}
                    for err in exc.errors()
                ],
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "internal_error",
                           "message": "unexpected server error (see structured logs)"}},
    )


@app.get("/api/openapi.json", include_in_schema=False)
def openapi_json():
    return app.openapi()


app.include_router(api_router, prefix=API_PREFIX)


@app.get(API_PREFIX.rstrip("/") + "/", include_in_schema=False)
def root():
    return {
        "name": "TRACE-X",
        "engine": ENGINE_VERSION,
        "ruleset": RULES_VERSION,
        "docs": "/docs",
        "layers": {
            "evidence": "what a source artifact directly records",
            "correlation": "how two or more observations relate",
            "hypothesis": "what a sequence may indicate, with uncertainty",
        },
        "policy": ("Correlation is never presented as causation; missing records are reported "
                   "as missing coverage, not as proven deletion."),
    }


# Serve a built frontend (frontend/dist) when present so the whole app can run
# from a single process. Dev mode uses the Vite dev server on :5173.
_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _dist.exists() and (_dist / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
    logger.info("serving built frontend from %s", _dist)