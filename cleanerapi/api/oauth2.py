import os
import typing
from dataclasses import dataclass
from urllib.parse import urlparse

import hikari
from coredis import Redis
from hikari.internal.time import utc_datetime
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic_ext import openapi, validate

from ..helpers.auth import UserInfo, UserToken, create_user_token
from ..security.fingerprint import fingerprint

bp = Blueprint("OAuth2Platform", "/oauth2/d", version=1)
required_scopes = (hikari.OAuth2Scope.IDENTIFY, hikari.OAuth2Scope.GUILDS)


@dataclass
class CodeAndState:
    code: str
    state: str
    redirect_uri: str


class ResponseModel:
    token: str
    guild_id: str | None


@bp.post("/finalize")
@openapi.summary("Finalize Discord OAuth2 flow")
@openapi.response(
    200, {"application/json": ResponseModel}, "Success. Response contains api key."
)
@openapi.response(400, {"text/plain": str}, "Invalid request")
@openapi.response(403, {"text/plain": str}, "Bad boy")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
@validate(json=CodeAndState)
async def post_authorize(
    request: Request,
    body: CodeAndState,
    database: Redis[bytes],
    hikari_rest: hikari.RESTApp,
) -> HTTPResponse:
    url = urlparse(body.redirect_uri)
    origin = request.headers.get("origin")
    if origin is None or url.hostname != urlparse(origin).hostname:
        return text("Invalid request source", 400)

    try:
        async with hikari_rest.acquire() as clientbot:
            authtoken = await clientbot.authorize_access_token(
                int(request.app.config.DISCORD_CLIENT_ID),
                request.app.config.DISCORD_CLIENT_SECRET,
                body.code,
                body.redirect_uri,
            )
    except hikari.BadRequestError:
        return text("Invalid code", 400)

    try:
        async with hikari_rest.acquire(authtoken.access_token, "Bearer") as selfbot:
            auth = await selfbot.fetch_authorization()

    except hikari.UnauthorizedError:
        return text("Connection has been deauthorized", 403)

    # no idea wtf mypy's issue is here
    missing_scopes = set(required_scopes) - set(auth.scopes)  # type: ignore
    if missing_scopes or auth.user is None:
        return text("Scope mismatch", 403)

    auth_object = {
        "token": authtoken.access_token,
        "scopes": " ".join(auth.scopes),
    }

    await database.hset(
        f"user:{auth.user.id}:oauth2",
        typing.cast(dict[str | bytes, str | bytes | int | float], auth_object),
    )
    await database.expireat(f"user:{auth.user.id}:oauth2", auth.expires_at)

    user_token = UserToken(
        auth.user.id,
        int(utc_datetime().timestamp()),
        int.from_bytes(os.urandom(8), "big"),
        0,
        fingerprint(request, "user")[:6],
    )

    # prefill cache
    user_object: UserInfo = {
        "id": str(auth.user.id),
        "name": auth.user.username,
        "discriminator": auth.user.discriminator,
        "avatar": auth.user.avatar_hash or "",
    }
    await database.hset(
        f"cache:user:{auth.user.id}",
        typing.cast(dict[str | bytes, str | bytes | int | float], user_object),
    )
    await database.expire(f"cache:user:{auth.user.id}", 30)

    return json(
        {
            "token": create_user_token(request, user_token),
            "guild_id": None if authtoken.guild is None else authtoken.guild.id,
        }
    )
