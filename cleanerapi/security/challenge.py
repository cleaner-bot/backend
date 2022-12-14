from __future__ import annotations

import hmac
import os
import random
import time
import typing
from base64 import b64encode
from binascii import crc32
from enum import Enum, auto
from functools import reduce
from operator import xor

from coredis import Redis
from httpx import AsyncClient
from pydantic import BaseModel, ValidationError, conint, constr
from sanic import HTTPResponse, Request, json, text

from ..helpers.based import b64parse
from .browserdetect import BrowserCheckVerdict, BrowserData, browser_check
from .captcha_providers import providers
from .fingerprint import fingerprint as fingerprint_request
from .proxy import is_request_from_proxy
from .trustzone import CompiledCode as TrustZone
from .trustzone import checks as trustzone_checks
from .trustzone import decrypt as decrypt_trustzone_result
from .trustzone import generate as generate_trustzone


class CaptchaRequirement(typing.NamedTuple):
    level: SecurityLevel
    unique: str


class SecurityLevel(Enum):
    DEFAULT = auto()
    CAPTCHA = auto()
    RAID = auto()


def generate_response(
    request: Request, unique: str, captcha_index: int, captchas: list[str]
) -> HTTPResponse | None:
    if captcha_index >= len(captchas):
        return None

    trustzone, trustzone_keys = generate_trustzone()

    iv = os.urandom(8)
    rnd = random.Random(
        iv + bytes.fromhex(request.app.config.BACKEND_ENCRYPTION_SECRET)
    )
    trustzone_bytes = b"".join(
        id.to_bytes(1, "big") + ekey.to_bytes(4, "big") for id, ekey in trustzone_keys
    )
    pad = rnd.randbytes(len(trustzone_bytes))
    encrypted_trustzone_keys = iv + bytes(
        x ^ pad[i] for i, x in enumerate(trustzone_bytes)
    )
    request_fp = fingerprint_request(request, "chl")
    timestamp = int(time.time())

    signature = hmac.new(
        bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
        (
            unique.encode()
            + captcha_index.to_bytes(2, "big")
            + timestamp.to_bytes(8, "big")
            + request_fp
            + encrypted_trustzone_keys
        ),
        "sha256",
    ).digest()

    captcha_provider = captchas[captcha_index]
    captcha_response: dict[str, str | int] = {"p": captcha_provider}
    providers[captcha_provider].challenge_parameters(
        request.app, captcha_response, signature=signature, unique=unique
    )
    response: dict[str, dict[str, str | int | TrustZone]] = {
        "c": typing.cast(dict[str, str | int | TrustZone], captcha_response),
        "d": {
            "h": b64encode(signature).decode(),
            "i": captcha_index,
            "t": timestamp,
            "vk": b64encode(encrypted_trustzone_keys).decode(),
            "v": trustzone,
        },
    }
    return json(response, 403)


class ChallengeRequestCaptchaData(BaseModel):
    h: typing.Annotated[str, constr(min_length=44, max_length=44)]
    i: typing.Annotated[int, conint(ge=0, lt=65535)]
    p: str
    t: int
    vk: str
    vc: int


class ChallengeRequest(BaseModel):
    c: ChallengeRequestCaptchaData
    b: list[int | str]
    p: typing.Any


def checksum(value: int | str) -> int:
    if isinstance(value, int):
        return crc32((value & 0xFFFFFFFF).to_bytes(4, "big"))
    return crc32(value.encode())


async def log_request(
    request: Request, fields: list[tuple[str, str, bool]], description: str
) -> None:
    http_client = typing.cast(AsyncClient, request.app.ctx.http_client)
    webhook = request.app.config.VERIFICATION_WEBHOOK
    await http_client.post(
        webhook,
        json={
            "embeds": [
                {
                    "description": description,
                    "fields": [
                        {"name": name, "value": value, "inline": inline}
                        for name, value, inline in fields
                    ],
                }
            ]
        },
    )


async def verify_request(
    request: Request, requirement: CaptchaRequirement
) -> HTTPResponse | None:
    database = typing.cast(Redis[bytes], request.app.ctx.database)
    captchas = ["button", "turnstile"]
    fields: list[tuple[str, str, bool]] = [
        ("Visitor IP", f"||{request.ip}||", True),
        ("Unique", requirement.unique, True),
        ("Level", requirement.level.name, True),
    ]

    if await database.exists((f"cache:ip:{request.ip}:banned",)):
        await log_request(request, fields, "IP is banned")
        return text("Ratelimit reached", 429)
    elif "b" not in request.json or "c" not in request.json:
        await log_request(request, fields, "Initial request")
        return generate_response(request, requirement.unique, 0, captchas)

    try:
        cr = ChallengeRequest.parse_obj(request.json)
    except ValidationError:
        await log_request(request, fields, "Invalid request")
        return generate_response(request, requirement.unique, 0, captchas)

    if (
        len(cr.b) % 2 == 1
        or not all(isinstance(x, int) for x in cr.b[1::2])
        or not all(
            checksum(cr.b[i]) ^ 0x735A20DC ^ crc32(bytes([i, 0x0C, 0x88, 0x59, 0xDD]))
            != cr.b[i + 1]
            for i in range(len(cr.b), 2)
        )
        or reduce(xor, map(checksum, cr.b)) != cr.c.vc & 0xFFFFFFFF
    ):
        await log_request(request, fields, "Checksum checks failed")
        return generate_response(request, requirement.unique, 0, captchas)

    signature = b64parse(cr.c.h)
    encrypted_trustzone_keys = b64parse(cr.c.vk)
    if (
        signature is None
        or len(signature) != 32
        or encrypted_trustzone_keys is None
        or cr.c.p not in providers
    ):
        await log_request(request, fields, "Invalid signature")
        return generate_response(request, requirement.unique, 0, captchas)

    request_fp = fingerprint_request(request, "chl")
    captcha_index = cr.c.i
    expected_signature = hmac.new(
        bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET),
        (
            requirement.unique.encode()
            + captcha_index.to_bytes(2, "big")
            + cr.c.t.to_bytes(8, "big")
            + request_fp
            + encrypted_trustzone_keys
        ),
        "sha256",
    ).digest()

    fields.extend(
        (
            ("Captcha stage", str(cr.c.i), False),
            ("CAPTCHA", f"{cr.c.i}/{cr.c.p}", True),
            ("Issue time", f"<t:{cr.c.t}>", True),
            ("Request FP", f"`{request_fp.hex()[:8]}...`", False),
        )
    )

    if not hmac.compare_digest(signature, expected_signature):
        await log_request(request, fields, "Signature check failed")
        return generate_response(request, requirement.unique, 0, captchas)
    elif time.time() > cr.c.t + 300:
        await log_request(request, fields, "Challenge timed out")
        return generate_response(request, requirement.unique, 0, captchas)

    rnd = random.Random(
        encrypted_trustzone_keys[:8]
        + bytes.fromhex(request.app.config.BACKEND_ENCRYPTION_SECRET)
    )
    pad = rnd.randbytes(len(encrypted_trustzone_keys) - 8)
    decrypted_trustzone_keys = bytes(
        x ^ pad[i] for i, x in enumerate(encrypted_trustzone_keys[8:])
    )
    trustzone_keys = [
        (
            decrypted_trustzone_keys[i],
            int.from_bytes(decrypted_trustzone_keys[i + 1 : i + 5], "big"),
        )
        for i in range(0, len(decrypted_trustzone_keys), 5)
    ]

    if 2 * len(trustzone_keys) != len(cr.b):
        await log_request(request, fields, "Invalid trustzone keys amount")
        return generate_response(request, requirement.unique, captcha_index, captchas)

    try:
        values = typing.cast(
            BrowserData,
            {
                trustzone_checks[no][0]: decrypt_trustzone_result(cr.b[2 * i], ekey)
                for i, (no, ekey) in enumerate(trustzone_keys)
            },
        )
    except UnicodeDecodeError:
        await log_request(request, fields, "Failed to decode challenge results")
        return generate_response(request, requirement.unique, captcha_index, captchas)

    if requirement.level == SecurityLevel.CAPTCHA:
        captchas.append("hcaptcha")
    elif requirement.level == SecurityLevel.RAID:
        captchas.extend(("pow", "hcaptcha"))

    print(values)
    result, fp, picasso = browser_check(request, values)

    print("browser check", fp, picasso)
    fields.extend(
        (
            ("Browser FP", f"`{fp.hex()[:8]}...`", True),
            ("Picasso", f"`{picasso:>08x}`", True),
            ("Browser result", result.verdict.name, False),
        )
    )
    if result.reason:
        fields.append(("Reason", result.reason, True))

    picasso_matching = await database.incr(f"cache:picasso:{picasso}")
    if picasso_matching == 1:
        await database.expire(f"cache:picasso:{picasso}", 300)

    if picasso_matching > 30:
        await log_request(request, fields, "Picasso limit reached")
        return text("Ratelimit reached", 429)

    match result.verdict:
        case BrowserCheckVerdict.AUTOMATED:
            await database.set(f"cache:ip:{request.ip}:banned", "1", ex=60)
            return text("Automation software detected", 403)
        case BrowserCheckVerdict.BAD_REQUEST:
            return text("Bad request", 400)
        case BrowserCheckVerdict.SUSPICIOUS:
            captchas.extend(("pow", "hcaptcha"))
        case BrowserCheckVerdict.TAMPERED:
            captchas.extend(
                ("pow", "hcaptcha", "turnstile", "button", "pow", "hcaptcha")
            )

    if (
        result.verdict != BrowserCheckVerdict.OK
        and requirement.level == SecurityLevel.RAID
    ):
        await log_request(request, fields, "Blocked due to raid")
        return text("Temporarily unavailable.", 403)

    if await is_request_from_proxy(request):
        fields.append(("Is proxy", ":white_check_mark:", False))
        if requirement.level == SecurityLevel.RAID:
            await log_request(request, fields, "Blocked due to raid")
            return text("Temporarily unavailable.", 403)
        captchas.append("hcaptcha")

    if cr.c.p != captchas[captcha_index]:
        await log_request(request, fields, "Solved unexpected CAPTCHA")
        return generate_response(request, requirement.unique, captcha_index, captchas)

    token = values["token"]
    if isinstance(token, str) and await providers[cr.c.p].verify(
        request, token=token, signature=signature, minimum_timestamp=cr.c.t
    ):
        fields.append(("CAPTCHA valid", ":white_check_mark:", False))
        captcha_index += 1
    else:
        fields.append(("CAPTCHA invalid", ":x:", False))

    return generate_response(request, requirement.unique, captcha_index, captchas)
