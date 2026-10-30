"""HTTP middlewares and centralized exception handling for the FastAPI application."""

import time
import uuid
from datetime import UTC, datetime

from cyberduel_contracts.system import ErrorDetail, StandardErrorResponse
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from apps.api.app.core.exceptions import CyberDuelException
from apps.api.app.core.logging import correlation_id_ctx, logger


class RequestCorrelationIdMiddleware(BaseHTTPMiddleware):
    """Assigns or propagates an X-Request-ID header to trace transactions."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        req_id = request.headers.get("X-Request-ID")
        if not req_id:
            req_id = f"cd-{uuid.uuid4().hex[:16]}"

        token = correlation_id_ctx.set(req_id)
        request.state.request_id = req_id

        start_time = time.perf_counter()
        try:
            response: Response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000
            response.headers["X-Request-ID"] = req_id
            response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
            return response
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.exception(f"Unhandled exception during request processing: {exc}")
            from apps.api.app.core.config import get_settings

            settings = get_settings()
            msg = str(exc) if settings.DEBUG else "An unexpected internal server error occurred."
            error_model = StandardErrorResponse(
                request_id=req_id,
                error_code="INTERNAL_SERVER_ERROR",
                message=msg,
                timestamp=datetime.now(UTC),
            )
            res = JSONResponse(status_code=500, content=error_model.model_dump(mode="json"))
            res.headers["X-Request-ID"] = req_id
            res.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
            return res
        finally:
            correlation_id_ctx.reset(token)


class RequestBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Protects memory by rejecting payloads exceeding max allowed bytes."""

    def __init__(self, app: ASGIApp, max_bytes: int = 1_048_576) -> None:
        super().__init__(app)
        self.default_max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        from apps.api.app.core.config import get_settings

        max_bytes = self.default_max_bytes or get_settings().MAX_REQUEST_BODY_BYTES
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > max_bytes:
                    req_id = getattr(request.state, "request_id", f"cd-{uuid.uuid4().hex[:16]}")
                    error_payload = StandardErrorResponse(
                        request_id=req_id,
                        error_code="PAYLOAD_TOO_LARGE",
                        message=f"Request body exceeds maximum permitted size of {max_bytes} bytes.",
                        timestamp=datetime.now(UTC),
                    )
                    return JSONResponse(
                        status_code=413,
                        content=error_payload.model_dump(mode="json"),
                    )
            except ValueError:
                pass
        res: Response = await call_next(request)
        return res


def register_exception_handlers(app: FastAPI, is_debug: bool = False) -> None:
    """Register centralized exception handlers mapping domain errors to canonical JSON schemas."""

    @app.exception_handler(CyberDuelException)
    async def cyberduel_exception_handler(
        request: Request, exc: CyberDuelException
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", f"cd-{uuid.uuid4().hex[:16]}")
        logger.warning(
            f"Domain exception [{exc.error_code}]: {exc.message} (status: {exc.status_code})"
        )
        details = [
            ErrorDetail(
                code=d.get("code", "ERROR"),
                message=d.get("message", "Error"),
                field=d.get("field"),
            )
            for d in exc.details
        ]
        response_model = StandardErrorResponse(
            request_id=req_id,
            error_code=exc.error_code,
            message=exc.message,
            details=details,
            timestamp=datetime.now(UTC),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=response_model.model_dump(mode="json"),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", f"cd-{uuid.uuid4().hex[:16]}")
        details: list[ErrorDetail] = []
        for err in exc.errors():
            loc = " -> ".join(str(part) for part in err.get("loc", []))
            details.append(
                ErrorDetail(
                    code="VALIDATION_ERROR",
                    message=err.get("msg", "Invalid field"),
                    field=loc or None,
                )
            )
        response_model = StandardErrorResponse(
            request_id=req_id,
            error_code="VALIDATION_FAILED",
            message="Request schema validation failed. Please check the supplied arguments.",
            details=details,
            timestamp=datetime.now(UTC),
        )
        return JSONResponse(
            status_code=422,
            content=response_model.model_dump(mode="json"),
        )

    @app.exception_handler(HTTPException)
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException | StarletteHTTPException
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", f"cd-{uuid.uuid4().hex[:16]}")
        msg = str(exc.detail)
        if len(msg) > 500:
            msg = msg[:497] + "..."
        response_model = StandardErrorResponse(
            request_id=req_id,
            error_code=f"HTTP_{exc.status_code}",
            message=msg,
            timestamp=datetime.now(UTC),
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=response_model.model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = getattr(request.state, "request_id", f"cd-{uuid.uuid4().hex[:16]}")
        logger.exception(f"Unhandled system error: {str(exc)}")
        message = str(exc) if is_debug else "An unexpected internal server error occurred."
        response_model = StandardErrorResponse(
            request_id=req_id,
            error_code="INTERNAL_SERVER_ERROR",
            message=message,
            timestamp=datetime.now(UTC),
        )
        return JSONResponse(
            status_code=500,
            content=response_model.model_dump(mode="json"),
        )
