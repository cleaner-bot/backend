import msgpack  # type: ignore
from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json
from sanic_ext import openapi


bp = Blueprint("GuildStatistics", version=1)


@bp.get("/guild/<guild:int>/statistics")
@openapi.secured("user")
@openapi.response(200, {"application/json": None}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def get_guild(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    statistics = await database.get(f"guild:{guild}:statistics")
    if statistics is None:
        return json(None)
    return json(msgpack.unpackb(statistics))
