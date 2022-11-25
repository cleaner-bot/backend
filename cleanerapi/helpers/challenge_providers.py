import hashlib
import json
import typing
from binascii import crc32

from httpx import AsyncClient
from sanic import Sanic

from .based import b64parse


async def verify_hcaptcha(app: Sanic, token: str, ip: str) -> bool:
    http_client = typing.cast(AsyncClient, app.ctx.http_client)
    res = await http_client.post(
        "https://hcaptcha.com/siteverify",
        data={
            "secret": app.config.HCAPTCHA_SECRET,
            "sitekey": app.config.HCAPTCHA_SITEKEY,
            "remoteip": ip,
            "response": token,
        },
    )
    data = typing.cast(HCaptchaResponse, res.json())
    print("hcaptcha -", data)
    return data["success"]


async def verify_turnstile(
    app: Sanic, token: str, ip: str, expected_cdata: str = ""
) -> bool:
    http_client = typing.cast(AsyncClient, app.ctx.http_client)
    res = await http_client.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": app.config.TURNSTILE_SECRET,
            "sitekey": app.config.TURNSTILE_SITEKEY,
            "remoteip": ip,
            "response": token,
        },
    )
    data = typing.cast(TurnstileResponse, res.json())
    print("turnstile -", data, expected_cdata)
    if expected_cdata != data.get("cdata", ""):
        return False
    return data["success"]


def verify_button(token: str) -> bool:
    decoded = b64parse(token)
    if decoded is None:
        print("button - not valid b64", token)
        return False
    secret_bytes = bytes([x ^ 0x86 ^ i for i, x in enumerate(decoded[:8])])
    secret = crc32(secret_bytes)
    trust = decoded[8] ^ (secret >> 16) & 0xFF
    if trust & 0x0F:
        print("button - click not trusted", trust)
        return False
    values = []
    for i in range(9, len(decoded), 2):
        v1 = decoded[i] ^ (secret >> 24)
        v2 = decoded[i + 1] ^ (secret & 0xFF)
        value = (v1 << 8) + v2
        values.append(value)
        secret ^= (value ^ (value << 8) ^ (value << 16) ^ (value << 24)) & 0xFFFFFFFF

    print("button - values", values)
    if len(values) != 10:
        print("button - wrong value length", len(values), values)
        return False

    offset_x, offset_y, page_x, page_y, x, y, scroll_x, scroll_y, top, left = values
    page_x -= left
    page_y -= top
    x += scroll_x - left
    y += scroll_y - top
    if top <= 0:
        print("button - invalid top", top)
    elif top <= 0:
        print("button - invalid left", left)

    coordinates = ((offset_x, offset_y), (page_x, page_y), (x, y))
    print("button - coordinates", coordinates)
    for vx, vy in coordinates:
        if not 303 >= vx >= 0:
            print("button - invalid vx", vx)
            return False
        elif not 78 >= vy >= 0:
            print("button - invalid vy", vy)
            return False

    all_x, all_y = zip(*coordinates)
    delta_x = abs(offset_x - sum(map(int, all_x)) / 3)
    delta_y = abs(offset_y - sum(map(int, all_y)) / 3)

    if delta_x > 4:
        print("button - too much x delta", delta_x, all_x)
        return False
    elif delta_y > 4:
        print("button - too much y delta", delta_y, all_y)
        return False

    return True


def verify_pow(token: str, prefix: bytes, difficulty: int = 17) -> bool:
    try:
        data = json.loads(token)
    except json.decoder.JSONDecodeError:
        print("pow - invalid json", token)
        return False

    result = data.get("result", None)
    if result is None or not isinstance(result, int) or not 0xFFFFFFFF >= result >= 0:
        print("pow - invalid pow result", result)
        return False

    digest = hashlib.sha256(prefix + result.to_bytes(4, "big")).digest()
    value = int.from_bytes(digest[-difficulty // 8 :], "big")

    if value & ((1 << difficulty) - 1):
        print("pow - not solved", bin(value))
        return False
    return True


HCaptchaResponse = typing.TypedDict(
    "HCaptchaResponse",
    {
        "success": bool,
        "challenge_ts": str,
        "hostname": str,
        "credit": bool,
        "error-codes": list[str],
    },
)
TurnstileResponse = typing.TypedDict(
    "TurnstileResponse",
    {
        "success": bool,
        "challenge_ts": str,
        "hostname": str,
        "error-codes": list[str],
        "action": str,
        "cdata": str,
    },
)
