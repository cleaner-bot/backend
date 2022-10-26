from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic.response import empty
from sanic_ext import openapi

from ...helpers.auth import is_developer
from ...helpers.rpc import rpc_call
from ...helpers.settings import (
    config_validators,
    default_entitlements,
    get_config,
    get_entitlements,
    set_config,
    set_entitlements,
)

bp = Blueprint("GuildSettings", version=1)


@bp.get("/guild/<guild:int>")
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
    guild_info = await rpc_call(database, "dash:guild-info", guild)
    config = await get_config(database, guild)
    entitlements = await get_entitlements(database, guild)

    if not guild_info["ok"]:
        if guild_info["message"] == "guild_not_found":
            return text("Guild not found", 404)
        return text(guild_info["message"], 503)

    return json(
        {
            "guild": {
                **guild_info["data"],
                "access": {
                    "type": request.ctx.guild["access_type"],
                    "requires_mfa": request.ctx.guild["requires_mfa"],
                },
            },
            "config": config,
            "entitlements": entitlements,
        }
    )


@bp.patch("/guild/<guild:int>/config")
@openapi.secured("user")
@openapi.body({"application/json": dict[str, str | int | float | bool]})
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def patch_guild_config(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    changes = request.json
    errors = {}
    for key, value in changes.items():
        if key not in config_validators:
            errors[key] = "unknown field"
        elif not config_validators[key](value):
            errors[key] = "invalid value"

    if errors:
        return json(errors, 400)

    await set_config(database, guild, changes)
    return empty()


@bp.patch("/guild/<guild:int>/entitlements")
@openapi.secured("user")
@openapi.body({"application/json": dict[str, str | int | float | bool]})
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def patch_guild_entitlements(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    if not is_developer(request.ctx.user_token.user_id):
        return text("Forbidden", 403)

    changes = request.json
    errors = {}
    for key in changes.keys():
        if key not in default_entitlements:
            errors[key] = "unknown field"

    if errors:
        return json(errors, 400)

    await set_entitlements(database, guild, changes)
    return empty()
