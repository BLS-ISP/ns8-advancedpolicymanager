"""FastAPI application factory, error handlers, and SPA static history fallback."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.auth.routes import router as auth_router
from app.config import Settings
from app.db.connection import DatabaseManager
from app.directory import DirectoryProvider, build_directory_provider
from app.errors import ApiError
from app.routes import (
    agent_router,
    assignments_router,
    dashboard_router,
    devices_router,
    enrollment_router,
    policies_router,
    simulator_router,
)

HTTP_STATUS_CODE_MAP = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    500: "INTERNAL_ERROR",
    503: "SERVICE_UNAVAILABLE",
}


def create_app(
    settings: Settings | None = None,
    directory_provider: DirectoryProvider | None = None,
) -> FastAPI:
    resolved_settings = settings if settings is not None else Settings.from_env()
    resolved_directory = (
        directory_provider
        if directory_provider is not None
        else build_directory_provider(resolved_settings)
    )
    db_manager = DatabaseManager(resolved_settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        db_manager.ensure_initialized()
        yield

    application = FastAPI(
        title="NS8-AdvancedPolicyManager API",
        version=__version__,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.directory_provider = resolved_directory
    application.state.db = db_manager
    application.state.revoked_jtis = set()

    @application.exception_handler(ApiError)
    async def handle_api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors(include_url=False)
        first_msg = errors[0].get("msg", "Ungültige Anfrageparameter") if errors else "Validierungsfehler"
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": str(first_msg),
                    "details": errors,
                }
            },
        )

    @application.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = HTTP_STATUS_CODE_MAP.get(exc.status_code, "HTTP_ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": code,
                    "message": str(exc.detail),
                    "details": None,
                }
            },
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_exception(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Interner Serverfehler",
                    "details": None,
                }
            },
        )

    application.include_router(dashboard_router)
    application.include_router(auth_router)
    application.include_router(policies_router)
    application.include_router(assignments_router)
    application.include_router(devices_router)
    application.include_router(simulator_router)
    application.include_router(enrollment_router)
    application.include_router(agent_router)

    @application.api_route(
        "/api/{unmatched_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        include_in_schema=False,
    )
    async def api_not_found(unmatched_path: str) -> JSONResponse:
        raise ApiError(404, "NOT_FOUND", f"API-Endpunkt '/api/{unmatched_path}' existiert nicht")

    @application.get("/{spa_path:path}", include_in_schema=False)
    async def serve_spa(spa_path: str) -> FileResponse:
        static_root: Path = resolved_settings.resolve_static_dir()
        index_file = static_root / "index.html"
        if not index_file.is_file():
            raise ApiError(
                404,
                "NOT_FOUND",
                "Web-Oberfläche ist nicht gebaut (index.html fehlt)",
            )

        clean_rel = spa_path.lstrip("/")
        if clean_rel:
            candidate = (static_root / clean_rel).resolve()
            if candidate.is_relative_to(static_root.resolve()) and candidate.is_file():
                return FileResponse(str(candidate))

        return FileResponse(str(index_file))

    return application


app = create_app()
