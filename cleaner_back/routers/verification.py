import os

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException
import msgpack  # type: ignore


from ..shared import (
    with_auth,
    with_database,
    aclient,
    has_entitlement,
    get_config,
    get_userme,
)
from ..models import ChallengerResponse, ChallengerRequest


router = APIRouter()


@router.get("/verification", response_model=ChallengerResponse)
async def get_verification(
    guild: int,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    if not await database.hexists(f"guild:{guild}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(
        database, guild, "verification_enabled"
    ):
        raise HTTPException(400, "Guild does not have verification enabled")
    
    user = await get_userme(database, user_id)

    splash = None
    if await has_entitlement(
        database, guild, "verification_custom_webpage"
    ):
        splash = await get_config(
            database, guild, "verification_webpage_splash"
        )

    return {
        "user": user,
        "is_valid": await database.exists((f"guild:{guild}:user:{user_id}:verification",)),
        "captcha_required": True,
        "splash": splash,
    }


@router.post("/verification", status_code=204)
async def post_verification(
    guild: int,
    body: ChallengerRequest,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    if not await database.hexists(f"guild:{guild}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(
        database, guild, "verification_enabled"
    ):
        raise HTTPException(400, "Guild does not have verification enabled")

    if not await database.exists((f"guild:{guild}:user:{user_id}:verification",)):
        raise HTTPException(404, "You are not pending verification.")

    is_captcha = body.token is not None  # TODO: captcha logic
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
                "response": body.token,
            },
        )
        data = res.json()
        if not data["success"]:
            raise HTTPException(400, "Invalid captcha token")

    await database.publish(
        "pubsub:verification-verify", 
        msgpack.packb({"guild": guild, "user": int(user_id)}),
    )
