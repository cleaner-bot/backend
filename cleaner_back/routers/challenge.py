import os

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException


from ..shared import (
    with_auth,
    with_optional_auth,
    with_database,
    aclient,
    has_entitlement,
    get_config,
    get_userme,
)
from ..models import ChallengerResponse, ChallengerRequest


router = APIRouter()


@router.get("/challenge", response_model=ChallengerResponse)
async def get_challenge(
    flow: str,
    auth_user_id: str = Depends(with_optional_auth),
    database: StrictRedis = Depends(with_database),
):
    if len(flow) != 64 or not all(x in "0123456789abcdef" for x in flow):
        raise HTTPException(400, "Invalid flow")
    user_id, guild_id, is_captcha = await database.hmget(
        f"challenge:flow:{flow}", ("user", "guild", "captcha")
    )
    if user_id is None or guild_id is None:
        raise HTTPException(404, "Flow not found")

    if not await database.hexists(f"guild:{int(guild_id)}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(
        database, guild_id.decode(), "challenge_interactive_enabled"
    ):
        await database.delete((f"challenge:flow:{flow}",))
        raise HTTPException(400, "Guild does not have interactive challenges enabled")

    user = await get_userme(database, auth_user_id)

    splash = None
    if await has_entitlement(
        database, guild_id.decode(), "challenge_interactive_custom_webpage"
    ):
        splash = await get_config(
            database, guild_id.decode(), "challenge_interactive_webpage_splash"
        )

    return {
        "user": user,
        "is_valid": user_id.decode() == auth_user_id,
        "captcha_required": is_captcha is not None,
        "splash": splash,
    }


@router.post("/challenge", status_code=204)
async def post_challenge(
    flow: str,
    body: ChallengerRequest | None = None,
    auth_user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    if len(flow) != 64 or not all(x in "0123456789abcdef" for x in flow):
        raise HTTPException(400, "Invalid flow")
    user_id, guild_id, is_captcha = await database.hmget(
        f"challenge:flow:{flow}", ("user", "guild", "captcha")
    )
    if user_id is None or guild_id is None:
        raise HTTPException(404, "Flow not found")

    if not await database.hexists(f"guild:{guild_id.decode()}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(
        database, guild_id.decode(), "challenge_interactive_enabled"
    ):
        await database.delete((f"challenge:flow:{flow}",))
        raise HTTPException(400, "Guild does not have interactive challenges enabled")

    if auth_user_id != user_id.decode():
        raise HTTPException(403, "Wrong user account")

    if (body is None or body.token is None) == is_captcha is not None:
        raise HTTPException(400, "Expected or unexpected captcha token")

    if is_captcha is not None and body is not None:
        hcaptcha_secret = os.getenv("SECRET_HCAPTCHA")
        hcaptcha_sitekey = os.getenv("HCAPTCHA_SITEKEY")
        if hcaptcha_secret is None or hcaptcha_sitekey is None:
            raise HTTPException(500, "Configuration issue, please contact support")
        res = await aclient.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": hcaptcha_secret,
                "sitekey": hcaptcha_sitekey,
                "response": body.token,
            },
        )
        data = res.json()
        if not data["success"]:
            raise HTTPException(400, "Invalid captcha token")

    await database.publish("pubsub:challenge-verify", flow)
