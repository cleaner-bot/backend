from __future__ import annotations

import hmac
from base64 import urlsafe_b64decode
from binascii import crc32

from coredis import Redis
from hikari import OAuth2Scope
from httpx import AsyncClient
from sanic import Blueprint, HTTPResponse, Request, Sanic, text
from sanic.exceptions import SanicException
from sanic.response import empty
from sanic_ext import openapi

from ..helpers.auth import UserInfo, get_user_guilds, parse_user_token
from ..helpers.rpc import rpc_call
from ..helpers.settings import get_config_field, get_entitlement_field
from ..security.challenge import CaptchaRequirement, SecurityLevel, verify_request

bp = Blueprint("HumanVerificationPlatform", "/chl", version=1)


class VerificationResponse:
    user: UserInfo | None
    is_valid: bool
    captcha_required: bool
    splash: str | None


@bp.post("")
@openapi.summary("challenge submit endpoint")
@openapi.body({"application/json": object})
@openapi.response(204, {}, "Verified")
@openapi.response(400, {"text/plain": str}, "Invalid request")
@openapi.response(401, {"text/plain": str}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "CAPTCHA verification required")
@openapi.response(404, {"text/plain": str}, "Already verified")
@openapi.response(409, {"text/plain": str}, "Guild does not have this enabled")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def post_human_challenge(
    request: Request, client: AsyncClient, database: Redis[bytes]
) -> HTTPResponse:
    body = request.json

    payload: dict[str, str] = body.get("p")

    if payload is None:
        return text("Missing 'p' in body", 400)
    elif "t" not in payload:
        return text("Missing 't' in body.p", 400)

    result: HTTPResponse | CaptchaRequirement
    if payload["t"] == "j":  # joinguard
        result = await check_join_guard(request, database, payload)
    elif payload["t"] == "v":  # verification
        result = await check_verification(request, database, payload)
    elif payload["t"] == "sv":  # super verification
        result = await check_super_verification(request, database, payload)
    else:
        return text("Invalid 't' in body.p", 400)

    if isinstance(result, HTTPResponse):
        return result  # bad request
    if r := await verify_request(request, result):
        return r

    if payload["t"] == "j":  # joinguard
        result = await complete_join_guard(request, database, payload)
    elif payload["t"] == "v":  # verification
        result = await complete_verification(request, database, payload)
    elif payload["t"] == "sv":  # super verificaiton
        result = await complete_super_verification(request, database, payload)

    if isinstance(result, HTTPResponse):
        return result

    return empty()


async def check_join_guard(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse | CaptchaRequirement:
    guild = payload.get("g")
    if guild is None:
        return text("Missing 'g' in body.p")
    elif not guild.isdigit():
        return text("Not an integer: body.p.g", 400)

    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401)

    if not await get_config_field(database, guild, "joinguard_enabled"):
        return text("Join Guard is not enabled", 409)
    plan = await get_entitlement_field(database, guild, "plan")
    joinguard = await get_entitlement_field(database, guild, "joinguard")
    if plan < joinguard:
        return text("Join Guard is not enabled", 409)

    tempbanned = await database.get(f"guild:{guild}:joinguard:{user_token.user_id}")
    if tempbanned is not None:
        return text(tempbanned.decode(), 400)

    guilds = await get_user_guilds(request, database)

    if any(x["id"] == guild for x in guilds):
        return text("Already joined", 404)

    token, scopes = await database.hmget(
        f"user:{user_token.user_id}:oauth2", ("token", "scopes")
    )
    if (
        token is None
        or scopes is None
        or OAuth2Scope.GUILDS_JOIN not in scopes.decode().split(" ")
    ):
        return text("Missing required scope", 401)

    if await database.scard(f"guild:{guild}:joinguard") >= 20:
        return CaptchaRequirement(SecurityLevel.RAID, f"j|{guild}")
    elif await get_config_field(database, guild, "joinguard_captcha"):
        return CaptchaRequirement(SecurityLevel.CAPTCHA, f"j|{guild}")

    return CaptchaRequirement(SecurityLevel.DEFAULT, f"j|{guild}")


async def complete_join_guard(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse:
    token = await database.hget(
        f"user:{request.ctx.user_token.user_id}:oauth2", "token"
    )
    if token is None:
        return text("token not found", 409)
    result = await rpc_call(
        database,
        "joinguard",
        int(payload["g"]),
        request.ctx.user_token.user_id,
        token.decode(),
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return empty()


async def check_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse | CaptchaRequirement:
    flow = payload.get("f")
    if flow is None:
        return text("Missing 'f' in body.p")

    user_id, guild_id = parse_flow(request.app, flow)

    request.ctx.flow_data = flow_data = await database.hgetall(
        f"verification:external:{guild_id}-{user_id}"
    )
    if not flow_data:
        return text("Already verified or link expired", 404)

    exists = await rpc_call(database, "dash:guild-check", (guild_id,))
    if not exists["ok"] or not exists["data"]:
        return text("Guild not found", 404)
    elif not await get_config_field(database, guild_id, "verification_enabled"):
        return text("Guild does not have verification enabled", 409)

    return CaptchaRequirement(SecurityLevel.DEFAULT, f"v|{user_id}|{guild_id}")


async def complete_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse:
    user_id, guild_id = parse_flow(request.app, payload["f"])

    result = await rpc_call(
        database,
        "verification:external:verify",
        user_id,
        guild_id,
        {k.decode(): v.decode() for k, v in request.ctx.flow_data.items()},
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return empty()


async def check_super_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse | CaptchaRequirement:
    guild = payload.get("g")
    if guild is None:
        return text("Missing 'g' in body.p")
    elif not guild.isdigit():
        return text("Not an integer: body.p.g", 400)

    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401)

    if not await get_config_field(database, guild, "super_verification_enabled"):
        return text("Super Verification is not enabled", 409)

    plan = await get_entitlement_field(database, guild, "plan")
    super_verification = await get_entitlement_field(
        database, guild, "super_verification"
    )
    if plan < super_verification:
        return text("Super Verification is not enabled", 409)

    guilds = await get_user_guilds(request, database)

    if all(x["id"] != guild for x in guilds):
        return text("User not in guild", 404)

    jointime = await database.hget(f"guild:{guild}:timelimit", str(user_token.user_id))
    if jointime is None:
        return text("Already verified", 404)

    danger = await database.hlen(f"guild:{guild}:timelimit")
    if danger >= 20:
        return CaptchaRequirement(SecurityLevel.RAID, f"sv{user_token.user_id}|{guild}")
    elif danger >= 10:
        return CaptchaRequirement(
            SecurityLevel.CAPTCHA, f"sv|{user_token.user_id}|{guild}"
        )

    if await get_config_field(database, guild, "super_verification_captcha"):
        return CaptchaRequirement(
            SecurityLevel.CAPTCHA, f"sv|{user_token.user_id}|{guild}"
        )

    return CaptchaRequirement(SecurityLevel.DEFAULT, f"sv|{user_token.user_id}|{guild}")


async def complete_super_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse:
    result = await rpc_call(
        database,
        "super-verification:verify",
        int(payload["g"]),
        request.ctx.user_token.user_id,
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return empty()


def parse_flow(app: Sanic, flow: str) -> tuple[int, int]:
    try:
        raw = urlsafe_b64decode(flow + "=" * (len(flow) % 4))
    except ValueError:
        raise SanicException("body.p.f is not base64 encoded", 400)

    if len(raw) != 52:
        raise SanicException("body.p.f must be 52 bytes long", 400)

    user_id = int.from_bytes(raw[0:8], "big")
    guild_id = int.from_bytes(raw[8:16], "big")
    checksum = int.from_bytes(raw[48:52], "big")
    if crc32(raw[:48]) != checksum:
        raise SanicException("Failed to valdiate body.p.f", 400)

    expected_hash = hmac.digest(
        bytes.fromhex(app.config.BACKEND_VERIFICATION_SECRET), raw[:16], "sha256"
    )
    if not hmac.compare_digest(expected_hash, raw[16:48]):
        raise SanicException("Failed to valdiate body.p.f", 400)

    return user_id, guild_id
