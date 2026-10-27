"""API router aggregation."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .accounts import router as accounts_router
from .admin import router as admin_router
from .analysis import router as analysis_router
from .auth import router as auth_router
from .data import router as data_router
from .investigations import ownership_guard, router as investigations_router

api_router = APIRouter()
# Any route carrying an investigation id (path or query) is ownership-gated
# in user-session mode; routes without one (health, rules, search …) are not.
_guard = [Depends(ownership_guard)]
api_router.include_router(accounts_router)
api_router.include_router(admin_router)
api_router.include_router(auth_router)
api_router.include_router(investigations_router, dependencies=_guard)
api_router.include_router(analysis_router, dependencies=_guard)
api_router.include_router(data_router, dependencies=_guard)

__all__ = ["api_router"]