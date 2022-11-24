import typing

from httpx import AsyncClient
from sanic import Sanic


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
    print("hcaptcha", data)
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
    print("turnstile", data, expected_cdata)
    if expected_cdata != data.get("cdata", ""):
        return False
    return data["success"]


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
