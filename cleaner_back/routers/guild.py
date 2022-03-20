import typing

from coredis import StrictRedis  # type: ignore
from fastapi import APIRouter, Depends, HTTPException
import msgpack  # type: ignore

from cleaner_conf.guild import GuildConfig, GuildEntitlements

from ..access import has_access, Access
from ..shared import (
    with_auth,
    with_database,
    limiter,
    has_entitlement,
    is_suspended,
    get_guilds,
    get_userme,
)
from ..models import DetailedGuildInfo, DownloadInfo, ChannelId


router = APIRouter()


async def check_guild(user_id: str, guild_id: str, database: StrictRedis):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        if guild["id"] == guild_id:
            return guild

    if has_access(user_id) and await database.exists(f"guild:{guild_id}:sync:added"):
        return {
            "id": guild_id,
            "name": "Placeholder",
            "icon": None,
            "is_owner": True,
            "is_admin": True,
            "has_access": False,
        }

    raise HTTPException(404, "Guild not found")


async def fetch_dict(database: StrictRedis, key: str, keys: typing.Sequence[str]):
    values = await database.hmget(key, *keys)
    return {k: msgpack.unpackb(v) for k, v in zip(keys, values) if v is not None}


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
    if has_access(user_id):
        user["is_dev"] = True

    if not await database.exists(
        f"guild:{guild_id}:sync:added"
    ) and not await is_suspended(database, guild_id):
        guild = None

    if guild is None:
        return {"user": user}

    guild_entitlements = await fetch_dict(
        database, "entitlements", tuple(GuildEntitlements.__fields__)
    )
    guild_config = await fetch_dict(database, "config", tuple(GuildConfig.__fields__))

    print(guild_entitlements, guild_config)

    data = {}
    for x in ("roles", "channels", "myself"):
        loaded = await database.get(f"guild:{guild_id}:sync:{x}")
        data[x] = None if loaded is None else msgpack.unpackb(loaded)

    return {
        "guild": {
            **data,
            "id": guild["id"],
            "name": guild["name"],
        },
        "entitlements": GuildEntitlements(**guild_entitlements),
        "config": GuildConfig(**guild_config),
        "user": user,
    }


@router.patch("/guild/{guild_id}/config", status_code=204)
async def patch_guild_config(
    guild_id: str,
    changes: dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not has_access(user_id):
        if await is_suspended(database, guild_id):
            raise HTTPException(403, "Guild is suspended")
        elif not await database.exists(f"guild:{guild_id}:sync:added"):
            raise HTTPException(404, "Guild not found")

    config = GuildConfig(**changes)
    as_dict = config.dict(exclude_unset=True)

    for key, value in as_dict.items():
        await database.hset(f"guild:{guild_id}:config", key, msgpack.packb(value))

    payload = {"guild_id": int(guild_id), "config": as_dict}
    await database.publish("pubsub:config-update", msgpack.packb(payload))


@router.patch("/guild/{guild_id}/entitlement", status_code=204)
async def patch_guild_entitlement(
    guild_id: str,
    changes: dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not has_access(user_id, Access.DEVELOPER):
        raise HTTPException(403, "No access")

    entitlememts = GuildEntitlements(**changes)
    as_dict = entitlememts.dict(exclude_unset=True)

    for key, value in as_dict.items():
        await database.hset(f"guild:{guild_id}:entitlememts", key, msgpack.packb(value))

    payload = {"guild_id": int(guild_id), "entitlememts": as_dict}
    await database.publish("pubsub:settings-update", msgpack.packb(payload))


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
    elif not await database.exists(f"guild:{guild_id}:sync:added"):
        raise HTTPException(404, "Guild not found")
    await database.publish(
        "pubsub:challenge-send",
        msgpack.packb({"guild": int(guild_id), "channel": request.channel_id}),
    )


@router.get("/guild/{guild_id}/logging/downloads", response_model=list[DownloadInfo])
async def get_guild_logging_downloads(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")
    elif not await database.exists(f"guild:{guild_id}:sync:added"):
        raise HTTPException(404, "Guild not found")
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
