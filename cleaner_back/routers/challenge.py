import json
from os import stat

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from hikari import Permissions, NotFoundError, UnauthorizedError, ChannelFollowerWebhook
from hikari.impl import RESTClientImpl

from ..shared import with_auth, with_optional_auth, with_database, hikari_rest, with_hikari, limiter, is_developer, aclient, has_entitlement


router = APIRouter(tags=["guild"])


@router.get("/challenge")
async def get_challenge(
    request: Request,
    response: Response,
    flow: str,
    auth_user_id: str = Depends(with_optional_auth),
    database: StrictRedis = Depends(with_database),
):
    if len(flow) != 64 or not all(x in "0123456789abcdef" for x in flow):
        raise HTTPException(400, "Invalid flow")
    user_id = await database.get(f"challenge:flow:{flow}:user")
    if user_id is None:
        raise HTTPException(404, "Flow not found")
    guild_id = await database.get(f"challenge:flow:{flow}:guild")
    
    is_captcha = await database.exists(f"challenge:flow:{flow}:captcha")

    splash = None
    if await has_entitlement(database, guild_id.decode(), "challenge_interactive_custom_webpage"):
        splash = await database.get(f"guild:{guild_id}:config:challenge_interactive_webpage_splash")
        if splash is not None:
            splash = splash.decode()
    

    return {
        "correct_account": user_id.decode() == auth_user_id,
        "logged_in": auth_user_id is not None,
        "captcha": is_captcha,
        "splash": splash
    }


@router.post("/challenge", status_code=204)
async def post_challenge(
    request: Request,
    response: Response,
    flow: str,
    captcha: str = None,
    auth_user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database)
):
    if len(flow) != 64 or not all(x in "0123456789abcdef" for x in flow):
        raise HTTPException(400, "Invalid flow")
    user_id = await database.get(f"challenge:flow:{flow}:user")
    if user_id is None:
        raise HTTPException(404, "Flow not found")

    is_captcha = await database.exists(f"challenge:flow:{flow}:captcha")

    if auth_user_id != user_id.decode():
        raise HTTPException(403, "Wrong user account")
    
    if (captcha is None) == is_captcha:
        raise HTTPException(400, "Expected or unexpected captcha token")
    
    if is_captcha:
        res = await aclient.post("https://hcaptcha.com/siteverify", data={
            "secret": "0x9f4B368033ca2415edfcb7dCb355966a8468B159",
            "sitekey": "10613019-10d8-4d66-a2fb-e83e6e6c80b7",
            "response": captcha,
        })
        data = res.json()
        if not data["success"]:
            raise HTTPException(400, "Invalid captcha token")
        
    # verified
    # TODO: hook up with bot
