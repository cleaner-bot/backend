import msgpack  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException
from hikari import OAuth2Scope

from ..schemas.models import ChallengerRequest, ChallengerResponseWithJoinScope
from ..schemas.types import TChallengerResponseWithJoinScope
from ..shared import (
    get_auth_object,
    get_config,
    get_userme,
    has_entitlement,
    verify_captcha,
    with_auth,
    with_database,
)

router = APIRouter()


@router.get("/joinguard", response_model=ChallengerResponseWithJoinScope)
async def get_verification(
    guild: int,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> TChallengerResponseWithJoinScope:
    if not await database.hexists(f"guild:{guild}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(database, guild, "joinguard_enabled"):
        raise HTTPException(400, "Guild does not have joinguard enabled")
    elif not await has_entitlement(database, guild, "joinguard"):
        raise HTTPException(400, "Guild does not have joinguard enabled")

    user = await get_userme(database, user_id)
    auth_object = await get_auth_object(database, user_id)

    splash = None
    if await has_entitlement(database, guild, "branding_splash"):
        if await get_config(database, guild, "branding_splash_enabled"):
            splash = f"https://cdn.cleanerbot.xyz/splash/{guild}"

    return {
        "user": user,
        "has_join_scope": OAuth2Scope.GUILDS_JOIN in auth_object["scopes"],
        "is_valid": await database.exists(
            (f"guild:{guild}:user:{user_id}:verification",)
        )
        > 0,
        "captcha_required": await get_config(database, guild, "joinguard_captcha"),
        "splash": splash,
    }


@router.post("/joinguard", status_code=204)
async def post_verification(
    guild: int,
    body: ChallengerRequest,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> None:
    if not await database.hexists(f"guild:{guild}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await get_config(database, guild, "joinguard_enabled"):
        raise HTTPException(400, "Guild does not have joinguard enabled")
    elif not await has_entitlement(database, guild, "joinguard"):
        raise HTTPException(400, "Guild does not have joinguard enabled")

    is_captcha = await get_config(database, guild, "joinguard_captcha")

    if (body is None or body.token is None) == (is_captcha is not None):
        raise HTTPException(400, "Expected or unexpected captcha token")

    if is_captcha:
        assert body.token
        await verify_captcha(body.token)

    await database.publish(
        "pubsub:joinguard",
        msgpack.packb({"guild": guild, "user": int(user_id)}),
    )
