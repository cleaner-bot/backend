import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json
from sanic_ext import openapi

from ...helpers.auth import get_user, is_developer

bp = Blueprint("UserInfo", version=1)


@bp.get("/user/me")
@openapi.secured("user")
@openapi.response(200, {"application/json": dict}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_user_me(request: Request, database: Redis[bytes]) -> HTTPResponse:
    user = typing.cast(dict[str, str | bool], await get_user(request, database))
    if is_developer(request.ctx.user_token.user_id):
        user["is_dev"] = True
    mfa_valid = (
        request.ctx.user_token.is_mfa_valid()
        and request.ctx.user_token.is_fingerprint_valid(request)
    )
    user["has_mfa"] = mfa_valid
    return json(user)
