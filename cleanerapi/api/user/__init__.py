from sanic import Blueprint, HTTPResponse, Request, text

from ...helpers.auth import parse_user_token
from . import bansync, guilds, info, mfa, statistics

user_bp = Blueprint.group(bansync.bp, guilds.bp, info.bp, mfa.bp, statistics.bp)


@user_bp.middleware("request")
async def authentication_middleware(request: Request) -> HTTPResponse | None:
    database = request.app.ctx.database
    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401)
    return None
