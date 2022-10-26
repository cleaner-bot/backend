import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic_ext import openapi

from ...helpers.auth import PartialGuildInfo, get_user_guilds
from ...helpers.rpc import rpc_call
from ...helpers.settings import get_entitlement_field

bp = Blueprint("UserGuilds", version=1)


@bp.get("/user/me/guilds")
@openapi.secured("user")
@openapi.response(200, {"application/json": list[PartialGuildInfo]}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def get_user_me_guilds(request: Request, database: Redis[bytes]) -> HTTPResponse:
    guilds = typing.cast(
        dict[int, dict[str, str | bool]],
        {
            int(x["id"]): x
            for x in await get_user_guilds(request, database)
            if x["access_type"] >= 0
        },
    )
    added_guild_ids = await rpc_call(database, "dash:guild-check", tuple(guilds.keys()))
    if not added_guild_ids["ok"]:
        return text(added_guild_ids["message"], 503)

    for guild_id, guild in guilds.items():
        guild["is_added"] = guild_id in added_guild_ids["data"]
        guild["is_suspended"] = bool(
            await get_entitlement_field(database, guild_id, "suspended")
        )
    return json(tuple(guilds.values()))
