import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic_ext import openapi

from ..helpers.auth import parse_user_token
from ..helpers.settings import validate_snowflake

bp = Blueprint("BanSyncGlobal", version=1)


@bp.get("/bansync")
@openapi.summary("resolves a ban list by its id (max 100)")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_bansync_lists(request: Request, database: Redis[bytes]) -> HTTPResponse:
    user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401)

    ids: list[str] = request.args.getlist("id", [])
    data: dict[str, PartialBanList | typing.Literal[False]] = {}
    for id in ids:
        if (
            id.isdigit()
            and validate_snowflake(id)
            and await database.exists((f"bansync:banlist:{id}",))
        ):
            name = await database.hget(f"bansync:banlist:{id}", "name")
            data[id] = {
                "count": await database.scard(f"bansync:banlist:{id}:users"),
                "name": name.decode() if name is not None else "untitled list",
            }
        else:
            data[id] = False
    return json(data)


class PartialBanList(typing.TypedDict):
    count: int
