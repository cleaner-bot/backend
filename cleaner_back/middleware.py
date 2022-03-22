import coredis
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.responses import Response, JSONResponse
from starlette.requests import Request


class DBConnectErrorMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, dispatch=None) -> None:
        super().__init__(app, dispatch)
        self.buckets = {}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        try:
            return await call_next(request)
        except coredis.ConnectionError:
            return JSONResponse({"detail": "No connection to database."}, 503)
