from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException

from ..schemas.models import ChallengerRequest, ChallengerResponse
from ..schemas.types import TChallengerResponse
from ..shared import (
    get_config,
    get_userme,
    has_entitlement,
    verify_captcha,
    with_database,
    with_optional_auth,
)

router = APIRouter()


@router.get("/challenge", response_model=ChallengerResponse)
async def get_challenge(
    flow: str,
    auth_user_id: str = Depends(with_optional_auth),
    database: Redis[bytes] = Depends(with_database),
) -> TChallengerResponse:
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
    if await has_entitlement(database, guild_id.decode(), "branding_splash"):
        if await get_config(database, guild_id.decode(), "branding_splash_enabled"):
            splash = f"https://cdn.cleanerbot.xyz/splash/{guild_id.decode()}"

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
    auth_user_id: str = Depends(with_optional_auth),
    database: Redis[bytes] = Depends(with_database),
) -> None:
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

    forced_captcha = is_captcha
    if auth_user_id != user_id.decode():
        if forced_captcha is not None:
            raise HTTPException(403, "Wrong user account")
        is_captcha = b"1"

    if (body is None or body.token is None) == (is_captcha is not None):
        raise HTTPException(400, "Expected or unexpected captcha token")

    if is_captcha is not None and body is not None:
        assert body.token
        await verify_captcha(body.token)

    await database.publish("pubsub:challenge-verify", flow)
