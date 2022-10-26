from coredis.exceptions import ConnectionError
from sanic import Request, HTTPResponse
from sanic.exceptions import SanicException
from sanic.handlers import ErrorHandler

db_error = SanicException("Failed to connect to database", 503)


class CustomErrorHandler(ErrorHandler):
    def default(self, request: Request, exception: BaseException) -> HTTPResponse:
        if isinstance(exception, ConnectionError):
            exception = db_error

        return super().default(request, exception)  # type: ignore
