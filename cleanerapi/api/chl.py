import base64
import hmac
import os
import random
import typing
from binascii import crc32

from coredis import Redis
from hikari import OAuth2Scope
from sanic import Blueprint, HTTPResponse, Request, Sanic, json, text
from sanic.exceptions import SanicException
from sanic.response import empty
from sanic_ext import openapi

from ..helpers.auth import UserInfo, get_user_guilds, parse_user_token
from ..helpers.based import b64parse
from ..helpers.challenge_providers import verify_hcaptcha, verify_turnstile
from ..helpers.fingerprint import fingerprint
from ..helpers.rpc import rpc_call
from ..helpers.settings import get_config_field, get_entitlement_field
from ..helpers.svm import svm

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
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    body = request.json

    payload: dict[str, str] = body.get("payload")

    if payload is None:
        return text("Missing 'payload' in body", 400)
    elif "type" not in payload:
        return text("Missing 'type' in body.payload", 400)

    result: HTTPResponse | str | bool = False
    if payload["type"] == "j":  # joinguard
        result = await check_join_guard(request, database, payload)
    elif payload["type"] == "v":  # verification
        result = await check_verification(request, database, payload)
    elif payload["type"] == "sv":  # super verificaiton
        result = await check_super_verification(request, database, payload)
    else:
        return text("Invalid 'type' in body.payload", 400)

    if isinstance(result, HTTPResponse):
        return result

    if result:
        if isinstance(result, bool):
            result = "turnstile"

        request_fingerprint = fingerprint(request, result + "-" + payload["type"])
        chldata: dict[str, str] | None = body.get("chldata")
        is_valid = True
        if (
            chldata is None
            or chldata.get("token", "") == ""
            or (parsed_token := b64parse(chldata["token"])) is None
            or chldata.get("ticket", "") == ""
            or (parsed_ticket := b64parse(chldata["ticket"])) is None
            or result != chldata.get("type")
            or len(parsed_ticket) != 96
            or not hmac.compare_digest(parsed_ticket[:32], request_fingerprint)
            or not hmac.compare_digest(
                hmac.digest(
                    bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
                    parsed_ticket[:-32],
                    "sha256",
                ),
                parsed_ticket[-32:],
            )
        ):
            is_valid = False

        if is_valid:
            assert chldata is not None  # redundant, but mypy :/
            svm_seed = parsed_ticket[32:64]  # type: ignore
            rnd = random.Random(svm_seed)
            svm_challenge = rnd.randbytes(4096)
            key = svm(svm_challenge)
            parsed_token_bytes = typing.cast(bytes, parsed_token)
            raw_token = bytes(
                x ^ key[i & 0xFF] for i, x in enumerate(parsed_token_bytes)
            )
            if (
                crc32(bytes(x ^ 0xFF for x in raw_token[:-4])).to_bytes(
                    4, "big", signed=False
                )
                != parsed_token_bytes[-4:]
            ):
                is_valid = False
            elif result == "hcaptcha":
                token = raw_token[:-4].decode()
                is_valid = await verify_hcaptcha(request.app, token, request.ip)
            elif result == "turnstile":
                token = raw_token[:-4].decode()
                cdata = parsed_ticket.hex()  # type: ignore
                is_valid = await verify_turnstile(request.app, token, request.ip, cdata)

        if not is_valid:
            svm_seed = os.urandom(32)
            raw_ticket = request_fingerprint + svm_seed
            raw_ticket += hmac.digest(
                bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
                raw_ticket,
                "sha256",
            )
            rnd = random.Random(svm_seed)
            svm_challenge = rnd.randbytes(4096)
            cdata = {
                "type": result,
                "ticket": base64.b64encode(raw_ticket).decode(),
                "svm": base64.b64encode(svm_challenge).decode().strip("="),
            }
            if result == "hcaptcha":
                cdata["sitekey"] = request.app.config.HCAPTCHA_SITEKEY
            elif result == "turnstile":
                cdata["sitekey"] = request.app.config.TURNSTILE_SITEKEY
                cdata["action"] = payload["type"]
                cdata["cdata"] = raw_ticket.hex()
            return json(cdata, 403)

    if payload["type"] == "j":  # joinguard
        result = await complete_join_guard(request, database, payload)
    elif payload["type"] == "v":  # verification
        result = await complete_verification(request, database, payload)
    elif payload["type"] == "sv":  # super verificaiton
        result = await complete_super_verification(request, database, payload)

    if isinstance(result, HTTPResponse):
        return result

    return empty()


async def check_join_guard(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse | bool | str:
    guild = payload.get("guild")
    if guild is None:
        return text("Missing 'guild' in body.payload")
    elif not guild.isdigit():
        return text("Not an integer: body.payload.guild", 400)

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
        return text("Already verified", 404)

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
        return "hcaptcha"
    elif await get_config_field(database, guild, "joinguard_captcha"):
        return True

    return False


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
        int(payload["guild"]),
        request.ctx.user_token.user_id,
        token.decode(),
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return empty()


async def check_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse | bool | str:
    flow = payload.get("flow")
    if flow is None:
        return text("Missing 'flow' in body.payload")

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

    return True


async def complete_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse:
    user_id, guild_id = parse_flow(request.app, payload["flow"])

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
) -> HTTPResponse | bool | str:
    guild = payload.get("guild")
    if guild is None:
        return text("Missing 'guild' in body.payload")
    elif not guild.isdigit():
        return text("Not an integer: body.payload.guild", 400)

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

    jointime = await database.hget(
        f"guild:{guild}:super-verification", str(user_token.user_id)
    )
    if jointime is None:
        return text("Already verified", 404)

    if await database.hlen(f"guild:{guild}:super-verification") >= 20:
        return "hcaptcha"

    if await get_config_field(database, guild, "super_verification_captcha"):
        return True

    return False


async def complete_super_verification(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> HTTPResponse:
    result = await rpc_call(
        database,
        "super-verification",
        int(payload["guild"]),
        request.ctx.user_token.user_id,
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return empty()


def parse_flow(app: Sanic, flow: str) -> tuple[int, int]:
    try:
        raw = base64.urlsafe_b64decode(flow + "=" * (len(flow) % 4))
    except ValueError:
        raise SanicException("body.payload.flow is not base64 encoded", 400)

    if len(raw) != 52:
        raise SanicException("body.payload.flow must be 52 bytes long", 400)

    user_id = int.from_bytes(raw[0:8], "big")
    guild_id = int.from_bytes(raw[8:16], "big")
    checksum = int.from_bytes(raw[48:52], "big")
    if crc32(raw[:48]) != checksum:
        raise SanicException("Failed to valdiate body.payload.flow", 400)

    expected_hash = hmac.digest(
        bytes.fromhex(app.config.BACKEND_VERIFICATION_SECRET), raw[:16], "sha256"
    )
    if not hmac.compare_digest(expected_hash, raw[16:48]):
        raise SanicException("Failed to valdiate body.payload.flow", 400)

    return user_id, guild_id
