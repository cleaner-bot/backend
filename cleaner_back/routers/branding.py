import hmac
import os
import re
from base64 import urlsafe_b64encode
from datetime import datetime

import msgpack  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException, Request

from ..schemas.models import VanityResponse
from ..schemas.types import TVanityResponse
from ..shared import (
    get_config,
    get_entitlement,
    has_entitlement,
    with_auth,
    with_database,
)
from .guild import check_guild, verify_guild_access

router = APIRouter()


def generate_upload_url(guild_id: str, category: str) -> str:
    key = os.getenv("backend/cdn-secret")
    if key is None:
        raise HTTPException(500, "Configuration issue, please contact support")

    asset = guild_id
    expire = int(datetime.now().timestamp() * 1000 + 60_000)

    data = f"{category}:{asset}:{expire}"
    mac = hmac.new(key.encode(), data.encode(), "sha256").digest()

    mac64 = urlsafe_b64encode(mac).decode().strip("=")
    return f"https://cdn.cleanerbot.xyz/{category}/{guild_id}/{expire}/{mac64}"


@router.post("/guild/{guild_id}/branding/assets/splash", response_model=str)
async def post_branding_splash_asset_url(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> str:
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "branding_splash")

    url = generate_upload_url(guild_id, "splash")
    return url


@router.put("/guild/{guild_id}/branding/vanity", status_code=204)
async def put_branding_vanity(
    guild_id: str,
    request: Request,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> None:
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "branding_vanity")

    vanity = (await request.body()).decode()
    old_vanity = await get_entitlement(database, guild_id, "branding_vanity_url")

    if vanity:
        if not re.fullmatch(r"[a-z\d-]{2,32}", vanity):
            raise HTTPException(400, "Vanity url is not qualified")
        elif await database.exists((f"vanity:{vanity}",)):
            raise HTTPException(400, "Vanity url is already taken")
    elif not old_vanity:
        raise HTTPException(400, "No vanity url set")

    if vanity:
        await database.set(f"vanity:{vanity}", guild_id)
    await database.delete((f"vanity:{old_vanity}",))

    operation = {"branding_vanity_url": msgpack.packb(vanity)}
    await database.hset(f"guild:{guild_id}:entitlements", operation)  # type: ignore
    payload = {"guild_id": int(guild_id), "entitlements": operation}
    await database.publish("pubsub:settings-update", msgpack.packb(payload))


@router.get("/vanity/{vanity}", response_model=VanityResponse)
async def get_vanity(
    vanity: str, database: Redis[bytes] = Depends(with_database)
) -> TVanityResponse:
    if not re.fullmatch(r"[a-z\d-]{2,32}", vanity):
        raise HTTPException(404, "Vanity not found")
    guild = await database.get(f"vanity:{vanity}")
    if guild is None:
        raise HTTPException(404, "Vanity not found")

    splash = False
    if await has_entitlement(database, guild.decode(), "branding_splash"):
        if await get_config(database, guild.decode(), "branding_splash_enabled"):
            splash = True

    return {
        "guild": guild.decode(),
        "splash": splash,
    }
