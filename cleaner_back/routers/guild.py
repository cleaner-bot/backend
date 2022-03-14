import json
import typing

from coredis import StrictRedis  # type: ignore
from fastapi import APIRouter, Depends, HTTPException

from cleaner_conf import ValidationError
from cleaner_conf.guild.config import config
from cleaner_conf.guild.entitlements import entitlements
from ..shared import (
    with_auth,
    with_database,
    limiter,
    is_developer,
    has_entitlement,
    is_suspended,
    get_guilds,
    get_userme,
)
from ..models import DetailedGuildInfo, DownloadInfo, ChannelId


router = APIRouter(tags=["guild"])


async def check_guild(user_id: str, guild_id: str, database: StrictRedis):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        if guild["id"] == guild_id:
            return guild
    raise HTTPException(404, "Guild not found")


@router.get("/guild/{guild_id}", response_model=DetailedGuildInfo)
async def get_guild(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    try:
        guild = await check_guild(user_id, guild_id, database)
    except HTTPException:
        guild = None

    user = await get_userme(database, user_id)
    if is_developer(user_id):
        user["is_dev"] = True

    if not await database.exists(f"guild:{guild_id}:sync:added"):
        guild = None

    if guild is None:
        return {"user": user}

    guild_entitlements = {
        k: v.decode()
        if (v := await database.get(f"guild:{guild_id}:entitlement:{k}")) is not None
        else value.to_string(value.default)
        for k, value in entitlements.items()
        if not value.hidden
    }
    guild_config = {
        k: v.decode()
        if (v := await database.get(f"guild:{guild_id}:config:{k}")) is not None
        else value.to_string(value.default)
        for k, value in config.items()
        if not value.hidden
    }

    data = {}
    for x in ("roles", "channels", "myself"):
        loaded = await database.get(f"guild:{guild_id}:sync:{x}")
        data[x] = None if loaded is None else json.loads(loaded)

    return {
        "guild": {
            **data,
            "id": guild["id"],
            "name": guild["name"],
        },
        "entitlements": guild_entitlements,
        "config": guild_config,
        "user": user,
    }


@router.patch("/guild/{guild_id}/config", status_code=204)
async def patch_guild_config(
    guild_id: str,
    changes: typing.Dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not is_developer(user_id) and await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")

    for key, value in changes.items():
        if key not in config:
            raise HTTPException(400, f"key not found: {key}")
        try:
            config[key].validate_string(value)
        except ValidationError as e:
            raise HTTPException(400, f"invalid value for {key}: {e.args[0]}")

    for key, value in changes.items():
        await database.set(f"guild:{guild_id}:config:{key}", value)

    payload = {"guild_id": int(guild_id), "table": "config", "changes": changes}
    await database.publish("pubsub:config-update", json.dumps(payload))


@router.patch("/guild/{guild_id}/entitlement", status_code=204)
async def patch_guild_entitlement(
    guild_id: str,
    changes: typing.Dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not is_developer(user_id):
        raise HTTPException(403, "Not developer")
    elif await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")

    for key, value in changes.items():
        if key not in entitlements:
            raise HTTPException(400, f"key not found: {key}")
        try:
            entitlements[key].validate_string(value)
        except ValidationError as e:
            raise HTTPException(400, f"invalid value for {key}: {e.args[0]}")

    for key, value in changes.items():
        await database.set(f"guild:{guild_id}:entitlement:{key}", value)

    payload = {"guild_id": int(guild_id), "table": "entitlements", "changes": changes}
    await database.publish("pubsub:config-update", json.dumps(payload))


@router.post("/guild/{guild_id}/challenge-embed", status_code=204)
@limiter.limit("2/10s")
async def post_guild_challenge_embed(
    guild_id: str,
    request: ChannelId,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")

    await database.publish(
        "pubsub:challenge-send",
        json.dumps({"guild": guild_id, "channel": request.channel_id}),
    )


@router.get(
    "/guild/{guild_id}/logging/downloads", response_model=typing.List[DownloadInfo]
)
async def get_guild_logging_downloads(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")
    elif not await has_entitlement(database, guild_id, "logging_downloads"):
        raise HTTPException(
            403, "Guild does not have the 'logging_downloads' entitlement"
        )

    return [
        {"year": 2021, "month": 10, "expired": True},
        {"year": 2021, "month": 11, "expired": True},
        {"year": 2021, "month": 12, "expired": False},
        {"year": 2022, "month": 1, "expired": False},
        {"year": 2022, "month": 2, "expired": False},
    ]
