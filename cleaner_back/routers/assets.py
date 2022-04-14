from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
import hmac
import os

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException

from .guild import check_guild
from ..shared import (
    has_entitlement,
    is_suspended,
    with_auth,
    with_database,
)


router = APIRouter()


def generate_upload_url(guild_id: str, category: str):
    key = os.getenv("SECRET_CDN_UPLOAD")
    if key is None:
        raise HTTPException(500, "Configuration issue, please contact support")

    asset = guild_id
    expire = int(datetime.now().timestamp() * 1000 + 60_000)

    data = f"{category}:{asset}:{expire}"
    mac = hmac.new(key.encode(), data.encode(), "sha256").digest()

    mac64 = urlsafe_b64encode(mac).decode().strip("=")
    return f"https://cleaner-cdn.leodev.xyz/{category}/{guild_id}/{expire}/{mac64}"


@router.post("/guild/{guild_id}/assets/splash", response_model=str)
async def get_guild(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")
    elif not await database.hexists(f"guild:{guild_id}:sync", "added"):
        raise HTTPException(404, "Guild not found")
    elif not await has_entitlement(database, guild_id, "branding_splash"):
        raise HTTPException(
            403, "Guild does not have the 'branding_splash' entitlement"
        )

    url = generate_upload_url(guild_id, "splash")
    return url
