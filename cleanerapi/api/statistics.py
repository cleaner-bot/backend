import msgpack  # type: ignore
from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json
from sanic_ext import openapi


bp = Blueprint("GlobalStatistics", version=1)


@bp.get("/statistics")
@openapi.response(200, {"application/json": None}, "Success")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def get_guild(request: Request, database: Redis[bytes]) -> HTTPResponse:
    statistics = await database.get("statistics:global")
    if statistics is None:
        return json(None)
    return json(msgpack.unpackb(statistics))
