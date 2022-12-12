import typing

from sanic import Blueprint, HTTPResponse, Request, text

from ...helpers.auth import get_user_guilds, is_developer, parse_user_token
from ...helpers.rpc import rpc_call
from ...helpers.settings import get_config_field, get_entitlement_field
from . import bansync, linkfilter, settings, statistics, verification

guild_bp = Blueprint.group(
    bansync.bp, settings.bp, verification.bp, statistics.bp, linkfilter.bp
)


@guild_bp.middleware("request")  # type: ignore
async def authentication_middleware(request: Request) -> HTTPResponse | None:
    database = request.app.ctx.database
    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401)

    guilds = await get_user_guilds(request, database)
    request.ctx.guilds = guilds

    guild_id = str(request.match_info.get("guild"))
    if not guild_id.isdigit():
        return text("Internal routing error", 500)

    matched_guild: dict[str, str | bool | int] | None = None

    is_dev = is_developer(user_token.user_id)
    for guild in guilds:
        if guild["id"] == guild_id and (is_dev or guild["access_type"] >= 0):
            matched_guild = typing.cast(dict[str, str | bool | int], guild)
            matched_guild["requires_mfa"] = guild["access_type"] < 0

    if matched_guild is None:
        if not is_dev:
            return text("Not Found", 404)

        # developer is trying to access a guild with the cleaner but without
        # being in it

        exists = await rpc_call(database, "dash:guild-check", (int(guild_id),))
        if not exists["ok"] or not exists["data"]:
            return text("Not Found", 404)

        matched_guild = {
            "id": guild_id,
            "name": "N/A (dev preview)",
            "icon": "",
            "access_type": 0,  # owner
            "requires_mfa": True,
        }
    elif not matched_guild["requires_mfa"]:
        matched_guild["requires_mfa"] = await get_config_field(
            database, guild_id, "access_mfa"
        )

    request.ctx.guild = matched_guild
    if request.method != "GET":
        suspended = await get_entitlement_field(database, guild_id, "suspended")
        if suspended:
            return text("Suspended - " + suspended, 403)

        if matched_guild["requires_mfa"] and (
            not user_token.is_mfa_valid()
            or not user_token.is_fingerprint_valid(request)
        ):
            return text("This action requires a verified MFA session", 403)

    return None
