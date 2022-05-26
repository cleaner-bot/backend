import os
import typing

import msgpack  # type: ignore
from cleaner_conf.guild import GuildConfig, GuildEntitlements
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from ..access import Access, has_access
from ..models import ChannelId, DetailedGuildInfo, StatisticsInfo
from ..shared import (
    get_entitlement,
    get_guilds,
    get_userme,
    has_entitlement,
    is_suspended,
    limiter,
    with_auth,
    with_database,
)

router = APIRouter()


async def check_guild(user_id: str, guild_id: str, database: Redis):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        if guild["id"] == guild_id and guild["access_type"] >= 0:
            return guild

    if has_access(user_id) and await database.hexists(
        f"guild:{guild_id}:sync", "added"
    ):
        return {
            "id": guild_id,
            "name": "Placeholder",
            "icon": None,
            "access_type": 0,
        }

    raise HTTPException(404, "Guild not found")


async def verify_guild_access(guild_id: str, database: Redis, entitlement: str = None):
    if await is_suspended(database, guild_id):
        raise HTTPException(403, "Guild is suspended")
    elif not await database.hexists(f"guild:{guild_id}:sync", "added"):
        raise HTTPException(404, "Guild not found")

    if entitlement is not None and not await has_entitlement(
        database, guild_id, entitlement
    ):
        raise HTTPException(403, f"Guild does not have the {entitlement!r} entitlement")


async def fetch_dict(database: Redis, key: str, keys: typing.Tuple[str, ...]):
    values = await database.hmget(key, keys)
    return {k: msgpack.unpackb(v) for k, v in zip(keys, values) if v is not None}


@router.get("/guild/{guild_id}", response_model=DetailedGuildInfo)
async def get_guild(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    try:
        guild = await check_guild(user_id, guild_id, database)
    except HTTPException:
        guild = None

    user = await get_userme(database, user_id)
    if has_access(user_id):
        user["is_dev"] = True

    if not await database.hexists(
        f"guild:{guild_id}:sync", "added"
    ) and not await is_suspended(database, guild_id):
        guild = None

    if guild is None:
        return {"user": user}

    guild_entitlements = await fetch_dict(
        database, f"guild:{guild_id}:entitlements", tuple(GuildEntitlements.__fields__)
    )
    guild_config = await fetch_dict(
        database, f"guild:{guild_id}:config", tuple(GuildConfig.__fields__)
    )

    myself, roles, channels = await database.hmget(
        f"guild:{guild_id}:sync", ("myself", "roles", "channels")
    )

    return {
        "guild": {
            "myself": None if myself is None else msgpack.unpackb(myself),
            "roles": None if roles is None else msgpack.unpackb(roles),
            "channels": None if channels is None else msgpack.unpackb(channels),
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
    changes: dict[str, typing.Any],
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not has_access(user_id):
        if await is_suspended(database, guild_id):
            raise HTTPException(403, "Guild is suspended")
        elif not await database.hexists(f"guild:{guild_id}:sync", "added"):
            raise HTTPException(404, "Guild not found")

    known_keys = set(GuildConfig.__fields__)
    unknown_keys = set(changes) - known_keys
    if unknown_keys:
        raise HTTPException(400, f"Unknown fields: {', '.join(unknown_keys)}")

    try:
        config = GuildConfig.parse_obj(changes)
    except ValidationError as e:
        raise HTTPException(422, e.errors())

    as_dict = config.dict(exclude_unset=True)
    if not as_dict:
        return

    await database.hset(
        f"guild:{guild_id}:config",
        {key: msgpack.packb(value) for key, value in as_dict.items()},
    )

    payload = {"guild_id": int(guild_id), "config": as_dict}
    await database.publish("pubsub:settings-update", msgpack.packb(payload))


@router.patch("/guild/{guild_id}/entitlement", status_code=204)
async def patch_guild_entitlement(
    guild_id: str,
    changes: dict[str, typing.Any],
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)

    if not has_access(user_id, Access.DEVELOPER):
        raise HTTPException(403, "No access")

    known_keys = set(GuildEntitlements.__fields__)
    unknown_keys = set(changes) - known_keys
    if unknown_keys:
        raise HTTPException(400, f"Unknown fields: {', '.join(unknown_keys)}")

    try:
        entitlements = GuildEntitlements.parse_obj(changes)
    except ValidationError as e:
        raise HTTPException(422, e.errors())

    as_dict = entitlements.dict(exclude_unset=True)
    if not as_dict:
        return

    await database.hset(
        f"guild:{guild_id}:entitlements",
        {key: msgpack.packb(value) for key, value in as_dict.items()},
    )

    payload = {"guild_id": int(guild_id), "entitlements": as_dict}
    await database.publish("pubsub:settings-update", msgpack.packb(payload))


@router.put("/guild/{guild_id}/worker", status_code=204)
async def put_worker(
    guild_id: str,
    request: Request,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "workers")

    body = await request.body()
    workers_size = await get_entitlement(database, guild_id, "workers_size")
    if len(body) > workers_size:
        raise HTTPException(400, "Script too large")

    await database.set(f"guild:{guild_id}:worker", body)
    payload = {"guild_id": int(guild_id), "worker": body}
    await database.publish("pubsub:settings-update", msgpack.packb(payload))


@router.post("/guild/{guild_id}/challenge-embed", status_code=204)
@limiter.limit("2/10s")
async def post_guild_challenge_embed(
    guild_id: str,
    request: ChannelId,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database)

    await database.publish(
        "pubsub:challenge-send",
        msgpack.packb({"guild": int(guild_id), "channel": request.channel_id}),
    )


@router.get("/guild/{guild_id}/backup/snapshot")
async def get_guild_snapshots(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "backup")

    return [
        {
            "id": snapshot_id.decode(),
            "timestamp": (snapshot := msgpack.unpackb(snapshot_raw))["timestamp"],
            "channels": len(snapshot["channels"]),
            "roles": len(snapshot["roles"]),
        }
        for snapshot_id, snapshot_raw in (
            await database.hgetall(f"guild:{guild_id}:backup:snapshots")
        ).items()
    ]


@router.post("/guild/{guild_id}/backup/snapshot", status_code=204)
@limiter.limit("3/m", "20/h")
async def post_guild_snaphost(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "backup")

    limit = await get_entitlement(database, guild_id, "backup_snapshot_limit")
    if await database.hlen(f"guild:{guild_id}:backup:snapshots") >= limit:
        raise HTTPException(403, "Snapshot limit reached")

    snapshot_id = os.urandom(16).hex()

    pubsub = database.pubsub()
    await pubsub.subscribe(f"pubsub:backup:snapshot:{snapshot_id}")

    await database.publish("pubsub:backup:snapshot", f"{guild_id}:{snapshot_id}")

    while True:
        message = await pubsub.get_message(timeout=10)

        if message is None:
            raise HTTPException(500, "Snapshot creation timed out")
        elif message["type"] == "message":
            break


@router.post("/guild/{guild_id}/backup/snapshot/{snapshot_id}")
@limiter.limit("3/1h")
async def post_apply_guild_snaphost(
    guild_id: str,
    snapshot_id: str,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "backup")

    if len(snapshot_id) != 32 or any(x not in "0123456789abcdef" for x in snapshot_id):
        raise HTTPException(400, "Invalid snapshot id")
    elif not await database.hexists(f"guild:{guild_id}:backup:snapshots", snapshot_id):
        raise HTTPException(404, "Snapshot not found")

    await database.publish("pubsub:backup:apply-snapshot", f"{guild_id}:{snapshot_id}")


@router.get("/guild/{guild_id}/statistics", response_model=StatisticsInfo)
async def get_guild_statistics(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis = Depends(with_database),
):
    await check_guild(user_id, guild_id, database)
    await verify_guild_access(guild_id, database, "statistics")

    data = await database.get(f"guild:{guild_id}:radar")
    if data is None:
        raise HTTPException(500, "No data available currently.")
    return msgpack.unpackb(data)
