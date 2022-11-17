from __future__ import annotations

import enum
import hmac
import os
import random
import typing
from base64 import b64encode, urlsafe_b64decode
from binascii import crc32
from datetime import datetime

from coredis import Redis
from hikari import OAuth2Scope
from httpx import AsyncClient
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


class RequiredCaptchaType(enum.Enum):
    DEFAULT = enum.auto()
    CAPTCHA = enum.auto()
    RAID = enum.auto()


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

    browserdata: dict[str, str | int] = body.get("d")
    payload: dict[str, str] = body.get("p")

    if payload is None:
        return text("Missing 'payload' in body", 400)
    elif "type" not in payload:
        return text("Missing 'type' in body.payload", 400)

    result: HTTPResponse | RequiredCaptchaType
    if payload["type"] == "j":  # joinguard
        result, unique = await check_join_guard(request, database, payload)
    elif payload["type"] == "v":  # verification
        result, unique = await check_verification(request, database, payload)
    elif payload["type"] == "sv":  # super verification
        result, unique = await check_super_verification(request, database, payload)
    else:
        return text("Invalid 'type' in body.payload", 400)

    if isinstance(result, HTTPResponse):
        return result  # bad request
    assert unique is not None

    captchas = ["turnstile"]
    if result == (RequiredCaptchaType.CAPTCHA, RequiredCaptchaType.RAID):
        captchas.append("hcaptcha")
    
    if not browser_check(request, browserdata):
        if result == RequiredCaptchaType.RAID:
            return text("Temporarily unavailable.", 403)
        captchas.append("hcaptcha")

    if await is_proxy(request, client, database):
        # dont allow proxies during raids
        if result == RequiredCaptchaType.RAID:
            return text("Temporarily unavailable.", 403)

        captchas.append("hcaptcha")

    if r := await verify(request, captchas, body.get("c"), unique):
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
                pass

            elif body["t"] < timestamp - 300_000:
                provider_index = body["t"]

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
            "svm": b64encode(svm_challenge).decode().strip("="),
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


def browser_check(request: Request, browserdata: BrowserData) -> bool:
    # check if payload makes sense
    browserdata_shape = {key: type(value) for key, value in browser_check.items()}
    if browserdata_shape != BrowserData.__annotations__:
        print("shape of browserdata does not match", browserdata_shape, browserdata)
        return False
    
    # check if the values make sense
    if browserdata["t1"] >= browserdata["t2"]:
        print("current before page load", browserdata)
        return False
    
    time_delta = abs(browserdata["t2"] - datetime.now().timestamp() * 1000)
    if time_delta > 60:
        print("time delta too large", time_delta, browserdata)
        return False
    
    # check if sequence number makes sense
    lower_bounds = (browserdata["t1"] + browserdata["t2"]) & 0xffff
    upper_bounds = (browserdata["t1"] + browserdata["t2"] + 1000) & 0xffff
    if lower_bounds > upper_bounds:  # its at the wrap around point
        if upper_bounds < browserdata["s"] < lower_bounds:
            print("sequence out of bounce (wrapped)", browserdata)
            return False
    else:
        if not upper_bounds >= browserdata["s"] >= lower_bounds:
            print("sequence out of bounce (not wrapped)", browserdata)
            return False
    
    browsers = {"webkit", "firefox", "chromium"}

    base_seed = bytearray((browserdata["t2"] & 0xffff_ffff).to_bytes(4, "big"))
    base_seed[0] ^= browserdata["s"] >> 8
    base_seed[1] ^= browserdata["s"] & 0xff
    base_seed[2] ^= browserdata["s"] >> 8
    base_seed[3] ^= browserdata["s"] & 0xff

    key = crc32(bytes([x ^ 181 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["m1"])
    if decoded is None:
        print("m1 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("m1", decrypted)
    if decrypted == b"1.9275814160560204e-50":
        browsers &= {"chromium"}
    elif decrypted == b"1.9275814160560206e-50":
        browsers &= {"webkit", "firefox"}
    else:
        print("invalid m1 value", decrypted)
        return False

    key = crc32(bytes([x ^ 40 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["m2"])
    if decoded is None:
        print("m2 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("m2", decrypted)
    if decrypted == b"1.046919966902314e+308":
        browsers &= {"firefox"}
    elif decrypted == b"1.0469199669023138e+308":
        browsers &= {"webkit", "chromium"}
    else:
        print("invalid m2 value", decrypted)
        return False

    if not browsers:
        print("conflicting math results")
        return False
    
    has_sec_fetch = "safari" not in browsers
    sec_fetch_headers = {"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"}
    if has_sec_fetch and request.headers.keys() & sec_fetch_headers != sec_fetch_headers:
        print("request does not have all required sec-fetch-* headers", browsers, tuple(request.headers.keys()))
        return False
    elif not has_sec_fetch and request.headers.keys() & sec_fetch_headers:
        print("request should not have sec-fetch-* headers", browsers, tuple(request.headers.keys()))
        return False

    has_sec_ch_ua = "chromium" in browsers
    sec_ch_ua_headers = {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
    if has_sec_ch_ua and request.headers.keys() & sec_ch_ua_headers != sec_ch_ua_headers:
        print("request does not have all required sec-ch-ua-* headers", browsers, tuple(request.headers.keys()))
        return False
    elif not has_sec_ch_ua and request.headers.keys() & sec_ch_ua_headers:
        print("request should not have sec-ch-ua-* headers", browsers, tuple(request.headers.keys()))
        return False

    key = crc32(bytes([x ^ 149 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["p1"])
    if decoded is None:
        print("p1 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("p1", decrypted)
    try:
        platform = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid p1 value", decrypted)
        return False
    
    if has_sec_ch_ua:
        sec_ch_ua_platform = request.headers.get("sec-ch-ua-platform")
        if platform != sec_ch_ua_platform:
            print("platform in sec-ch-ua-platform header does not match", platform, sec_ch_ua_platform)
            return False
    
    key = crc32(bytes([x ^ 67 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l1"])
    if decoded is None:
        print("l1 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l1", decrypted)
    try:
        url = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l1 value", decrypted)
        return False
    
    key = crc32(bytes([x ^ 114 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l2"])
    if decoded is None:
        print("l2 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l2", decrypted)
    try:
        locale = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l2 value", decrypted)
        return False
    
    accept_language = request.headers.get("accept-language")
    if accept_language is None or locale not in accept_language:
        print("invalid lcoale", locale, accept_language)
        return False
    
    key = crc32(bytes([x ^ 184 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l3"])
    if decoded is None:
        print("l3 is not valid base64", browserdata)
        return False
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l3", decrypted)
    try:
        intl_check = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l3 value", decrypted)
        return False

    if intl_check.count("|") != 1:
        print("invalid l3 | count", intl_check)
        return False
    # firefox seems to have issues with this
    elif intl_check.split("|")[0] != intl_check.split("|")[1] and "firefox" not in browsers:
        print("invalid l3 values", intl_check)
        return False
    
    return True


class BrowserData(typing.TypedDict):
    t1: int
    t2: int
    s: int
    m1: str
    m2: str
    p1: str
    l1: str
    l2: str
    l3: str



async def is_proxy(
    request: Request, client: AsyncClient, database: Redis[bytes]
) -> bool:
    cached = await database.get(f"cache:ip:{request.ip}")
    if cached is not None:
        return cached == b"1"
    asn = typing.cast(str, request.headers["X-Connecting-Asn"])
    if await database.sismember("cache:hosting-asn", asn):
        return True
    # cannot use https without paying, wtf?
    response = await client.get(
        f"http://ip-api.com/json/{request.ip}?fields=status,mobile,proxy,hosting"
    )
    response.raise_for_status()
    data = response.json()
    print("ipcheck", data)
    is_proxy = data["proxy"] or data["hosting"]
    if data["hosting"]:
        await database.sadd("cache:hosting-asn", (asn,))
    await database.set(f"cache:ip:{request.ip}", "1" if is_proxy else "0", ex=60 * 60)
    return bool(is_proxy)


async def check_join_guard(
    request: Request, database: Redis[bytes], payload: dict[str, str]
) -> tuple[HTTPResponse | RequiredCaptchaType, str]:
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
        return text("Already joined", 404), ""

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
        return RequiredCaptchaType.RAID, f"j|{guild}"
    elif await get_config_field(database, guild, "joinguard_captcha"):
        return RequiredCaptchaType.CAPTCHA, f"j|{guild}"

    return RequiredCaptchaType.DEFAULT, f"j|{guild}"


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
) -> tuple[HTTPResponse | RequiredCaptchaType, str]:
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

    return RequiredCaptchaType.CAPTCHA, f"v|{user_id}|{guild_id}"


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
) -> tuple[HTTPResponse | RequiredCaptchaType, str]:
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
        return RequiredCaptchaType.RAID, f"sv{user_token.user_id}|{guild}"
    elif danger >= 10:
        return RequiredCaptchaType.CAPTCHA, f"sv|{user_token.user_id}|{guild}"

    if await get_config_field(database, guild, "super_verification_captcha"):
        return RequiredCaptchaType.CAPTCHA, f"sv|{user_token.user_id}|{guild}"

    return RequiredCaptchaType.DEFAULT, f"sv|{user_token.user_id}|{guild}"


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
