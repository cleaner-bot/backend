import os

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException


from ..shared import (
    with_auth,
    with_database,
    aclient,
    has_entitlement,
    get_config,
)
from ..models import Challenge


router = APIRouter()


@router.post("/verification", status_code=204)
async def post_verification(
    guild_id: int,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    if not await database.hexists(f"guild:{guild_id}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(
        database, guild_id, "verification_enabled"
    ):
        raise HTTPException(400, "Guild does not have verification enabled")

    is_captcha = False  # TODO: captcha logic
    if is_captcha:
        hcaptcha_secret = os.getenv("SECRET_HCAPTCHA")
        hcaptcha_sitekey = os.getenv("SECRET_HCAPTCHA_SITEKEY")
        if hcaptcha_secret is None or hcaptcha_sitekey is None:
            raise HTTPException(500, "Configuration issue, please contact support")
        res = await aclient.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": hcaptcha_secret,
                "sitekey": hcaptcha_sitekey,
                # "response": challenge.captcha,
            },
        )
        data = res.json()
        if not data["success"]:
            raise HTTPException(400, "Invalid captcha token")

    await database.publish("pubsub:verification-verify", user_id)
