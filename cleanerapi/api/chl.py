import hmac
import os
import random
import typing
from base64 import b64encode, urlsafe_b64decode
from binascii import crc32
from datetime import datetime

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

    result: HTTPResponse | list[str] | bool = False
    if payload["type"] == "j":  # joinguard
        result, unique = await check_join_guard(request, database, payload)
    elif payload["type"] == "v":  # verification
        result, unique = await check_verification(request, database, payload)
    elif payload["type"] == "sv":  # super verificaiton
        result, unique = await check_super_verification(request, database, payload)
    else:
        return text("Invalid 'type' in body.payload", 400)

    if isinstance(result, HTTPResponse):
        return result  # bad request

    if result:
        if isinstance(result, bool):
            result = ["turnstile"]
        assert unique is not None
        if r := await verify(request, result, body.get("chldata"), unique):
            return r

    if payload["type"] == "j":  # joinguard
        result = await complete_join_guard(request, database, payload)
    elif payload["type"] == "v":  # verification
        result = await complete_verification(request, database, payload)
    elif payload["type"] == "sv":  # super verificaiton
        result = await complete_super_verification(request, database, payload)

    if isinstance(result, HTTPResponse):
        return result

    return empty()


async def verify(
    request: Request, captcha_providers: list[str], body: typing.Any, unique: str
) -> HTTPResponse | None:
    timestamp = int(datetime.now().timestamp() * 1000)
    request_fingerprint = fingerprint(request, "chl")
    provider_index = 0
    if (
        isinstance(body, dict)
        and body.get("s1", "") != ""
        and (chl_svm_seed := b64parse(body["s1"])) is not None
        and body.get("h", "") != ""
        and (chl_signature := b64parse(body["h"])) is not None
        and body.get("token", "") != ""
        and (chl_token := b64parse(body["token"])) is not None
        and isinstance(body.get("i", ""), int)
        and isinstance(body.get("t", ""), int)
    ):
        expected_signature = hmac.new(
            bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
            unique.encode()
            + body["i"].to_bytes(4, "big")
            + body["t"].to_bytes(8, "big")
            + request_fingerprint
            + chl_svm_seed,
            "sha256",
        ).digest()
        if hmac.compare_digest(expected_signature, chl_signature):
            rnd = random.Random(chl_svm_seed)
            svm_challenge = rnd.randbytes(4096)
            key = svm(svm_challenge)
            raw_token = bytes(x ^ key[i & 0xFF] for i, x in enumerate(chl_token))
            challenge_provider = captcha_providers[body["i"]]
            if (
                crc32(bytes(x ^ 0xFF for x in raw_token[:-4])).to_bytes(
                    4, "big", signed=False
                )
                != chl_token[-4:]
            ):
                print("failed crc32 checksum")

            elif body["t"] < timestamp - 300_000:
                provider_index = body["t"]
                print("timeout", body, timestamp)

            elif challenge_provider == "hcaptcha":
                token = raw_token[:-4].decode()
                if await verify_hcaptcha(request.app, token, request.ip):
                    provider_index = body["i"] + 1

            elif challenge_provider == "turnstile":
                token = raw_token[:-4].decode()
                if await verify_turnstile(
                    request.app, token, request.ip, chl_signature.hex()
                ):
                    provider_index = body["i"] + 1

    if provider_index >= len(captcha_providers):
        return None

    svm_seed = os.urandom(32)
    rnd = random.Random(svm_seed)
    svm_challenge = rnd.randbytes(4096)
    signature = hmac.new(
        bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
        unique.encode()
        + provider_index.to_bytes(4, "big")
        + timestamp.to_bytes(8, "big")
        + request_fingerprint
        + svm_seed,
        "sha256",
    ).digest()

    challenge_provider = captcha_providers[provider_index]
    challenge: dict[str, dict[str, str | int]] = {
        "captcha": {"provider": challenge_provider},
        "d": {
            # "fp": request_fingerprint.hex(),
            "svm": b64encode(svm_challenge).decode(),
            "s1": b64encode(svm_seed).decode(),
            "h": b64encode(signature).decode(),
            "i": provider_index,
            "t": timestamp,
        },
    }

    if challenge_provider == "turnstile":
        challenge["captcha"].update(
            {
                "sitekey": request.app.config.TURNSTILE_SITEKEY,
                "action": unique.split("|")[0],
                "cdata": signature.hex(),
            }
        )
    elif challenge_provider == "hcaptcha":
        challenge["captcha"]["sitekey"] = request.app.config.HCAPTCHA_SITEKEY

    return json(challenge, 403)


async def check_join_guard(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> tuple[HTTPResponse | bool | list[str], str]:
    guild = payload.get("guild")
    if guild is None:
        return text("Missing 'guild' in body.payload"), ""
    elif not guild.isdigit():
        return text("Not an integer: body.payload.guild", 400), ""

    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401), ""

    if not await get_config_field(database, guild, "joinguard_enabled"):
        return text("Join Guard is not enabled", 409), ""
    plan = await get_entitlement_field(database, guild, "plan")
    joinguard = await get_entitlement_field(database, guild, "joinguard")
    if plan < joinguard:
        return text("Join Guard is not enabled", 409), ""

    tempbanned = await database.get(f"guild:{guild}:joinguard:{user_token.user_id}")
    if tempbanned is not None:
        return text(tempbanned.decode(), 400), ""

    guilds = await get_user_guilds(request, database)

    if any(x["id"] == guild for x in guilds):
        return text("Already verified", 404), ""

    token, scopes = await database.hmget(
        f"user:{user_token.user_id}:oauth2", ("token", "scopes")
    )
    if (
        token is None
        or scopes is None
        or OAuth2Scope.GUILDS_JOIN not in scopes.decode().split(" ")
    ):
        return text("Missing required scope", 401), ""

    if await database.scard(f"guild:{guild}:joinguard") >= 20:
        return ["hcaptcha"], f"j|{guild}"
    elif await get_config_field(database, guild, "joinguard_captcha"):
        return True, f"j|{guild}"

    return False, ""


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
) -> tuple[HTTPResponse | bool | list[str], str]:
    flow = payload.get("flow")
    if flow is None:
        return text("Missing 'flow' in body.payload"), ""

    user_id, guild_id = parse_flow(request.app, flow)

    request.ctx.flow_data = flow_data = await database.hgetall(
        f"verification:external:{guild_id}-{user_id}"
    )
    if not flow_data:
        return text("Already verified or link expired", 404), ""

    exists = await rpc_call(database, "dash:guild-check", (guild_id,))
    if not exists["ok"] or not exists["data"]:
        return text("Guild not found", 404), ""
    elif not await get_config_field(database, guild_id, "verification_enabled"):
        return text("Guild does not have verification enabled", 409), ""

    return True, f"v|{user_id}|{guild_id}"


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
) -> tuple[HTTPResponse | bool | list[str], str]:
    guild = payload.get("guild")
    if guild is None:
        return text("Missing 'guild' in body.payload"), ""
    elif not guild.isdigit():
        return text("Not an integer: body.payload.guild", 400), ""

    request.ctx.user_token = user_token = await parse_user_token(request, database)
    if user_token is None:
        return text("Unauthorized", 401), ""

    if not await get_config_field(database, guild, "super_verification_enabled"):
        return text("Super Verification is not enabled", 409), ""

    plan = await get_entitlement_field(database, guild, "plan")
    super_verification = await get_entitlement_field(
        database, guild, "super_verification"
    )
    if plan < super_verification:
        return text("Super Verification is not enabled", 409), ""

    guilds = await get_user_guilds(request, database)

    if all(x["id"] != guild for x in guilds):
        return text("User not in guild", 404), ""

    jointime = await database.hget(
        f"guild:{guild}:super-verification", str(user_token.user_id)
    )
    if jointime is None:
        return text("Already verified", 404), ""

    danger = await database.hlen(f"guild:{guild}:super-verification")
    if danger >= 20:
        return ["hcaptcha"], f"sv{user_token.user_id}|{guild}"
    elif danger >= 10:
        return True, f"sv|{user_token.user_id}|{guild}"

    if await get_config_field(database, guild, "super_verification_captcha"):
        return True, f"sv|{user_token.user_id}|{guild}"

    return False, ""


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
        raw = urlsafe_b64decode(flow + "=" * (len(flow) % 4))
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
