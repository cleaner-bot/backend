import asyncio
import os
from datetime import datetime

import hikari
import msgpack  # type: ignore
from cleaner_conf.guild import GuildConfig, GuildEntitlements
from coredis import Redis
from fastapi import Depends, Header, HTTPException
from hikari import Permissions, RESTApp, UnauthorizedError
from httpx import AsyncClient
from jose import jws  # type: ignore
from slowerapi import IPJail, Limiter, get_visitor_ip
from slowerapi.jail import ReportFunc
from slowerapi.reporters.cf import CloudflareIPAccessRuleReporter

home = "https://cleanerbot.xyz"
redis_db = os.getenv("REDIS_URL")
redis = Redis.from_url(redis_db) if redis_db is not None else Redis()
aclient = AsyncClient(headers={"user-agent": "CleanerBot (cleanerbot.xyz 0.1.0)"})
hikari_rest = RESTApp()


def with_database() -> Redis:
    return redis


def with_asyncclient() -> AsyncClient:
    return aclient


async def with_hikari() -> RESTApp:
    return hikari_rest


async def with_auth(
    x_token: str = Header(None), database: Redis = Depends(with_database)
):
    if x_token is None:
        raise HTTPException(401, "Missing X-Token header")

    secret = os.getenv("backend/jwt-secret")
    try:
        data = jws.verify(x_token, secret, algorithms=["HS256"])
    except jws.JWSError:
        raise HTTPException(401, "Invalid X-Token header")

    expires, session, userid = data.decode().split(".")

    if datetime.utcfromtimestamp(int(expires)) < datetime.utcnow():
        raise HTTPException(401, "Session expired")

    session_exists = await database.exists((f"user:{userid}:dash:session:{session}",))
    if not session_exists:
        raise HTTPException(401, "Session revoked")

    return userid


async def with_optional_auth(
    x_token: str = Header(None), database: Redis = Depends(with_database)
):
    try:
        return await with_auth(x_token, database)
    except HTTPException:
        return None


async def has_entitlement(
    database: Redis, guild_id: str | int, entitlement: str
) -> bool:
    value = await database.hget(f"guild:{guild_id}:entitlements", entitlement)
    if value is None:
        value = GuildEntitlements.__fields__[entitlement].default
    else:
        value = msgpack.unpackb(value)

    if value == 0:
        return True

    plan = await database.hget(f"guild:{guild_id}:entitlements", "plan")
    if plan is None:
        return False

    return msgpack.unpackb(plan) >= value


async def is_suspended(database: Redis, guild_id: str | int) -> bool:
    return await get_entitlement(database, guild_id, "suspended")


async def get_entitlement(database: Redis, guild_id: str | int, name: str) -> bool:
    value = await database.hget(f"guild:{guild_id}:entitlements", name)
    if value is None:
        return GuildEntitlements.__fields__[name].default
    return getattr(GuildEntitlements(**{name: msgpack.unpackb(value)}), name)


async def get_config(database: Redis, guild_id: str | int, name: str):
    value = await database.hget(f"guild:{guild_id}:config", name)
    if value is None:
        return GuildConfig.__fields__[name].default
    return getattr(GuildConfig(**{name: msgpack.unpackb(value)}), name)


get_guilds_lock: dict[str, asyncio.Event] = {}
get_user_lock: dict[str, asyncio.Event] = {}


async def get_guilds(database: Redis, user_id: str):
    cached = await database.get(f"cache:user:{user_id}:guilds")
    if cached is not None:
        return msgpack.unpackb(cached)

    access_token = await database.get(f"user:{user_id}:oauth:token")
    if access_token is None:
        raise HTTPException(401, "Session expired")

    print("guild cache missed", user_id in get_guilds_lock and "locked" or "locking")
    if user_id in get_guilds_lock:
        await get_guilds_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}:guilds")
        if cached is not None:
            return msgpack.unpackb(cached)

    get_guilds_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(access_token.decode(), "Bearer") as selfbot:
            guilds = await selfbot.fetch_my_guilds()

    except UnauthorizedError:
        await database.delete((f"user:{user_id}:oauth:token",))
        raise HTTPException(401, "Session expired")

    finally:
        get_guilds_lock[user_id].set()
        del get_guilds_lock[user_id]

    guildobj = [
        {
            "id": str(guild.id),
            "name": guild.name,
            "icon": guild.icon_hash,
            "access_type": await get_access_type(database, guild, user_id),
        }
        for guild in guilds
    ]

    await database.set(f"cache:user:{user_id}:guilds", msgpack.packb(guildobj), ex=30)

    return guildobj


async def get_access_type(database: Redis, guild: hikari.OwnGuild, user_id: str):
    if guild.is_owner:
        return 0
    permissions = await get_config(database, guild.id, "access_permissions")
    if permissions and guild.my_permissions & Permissions.ADMINISTRATOR:
        return 1
    elif permissions == 2 and guild.my_permissions & Permissions.MANAGE_GUILD:
        return 2

    # TODO: roles

    members = await get_config(database, guild.id, "access_members")
    if user_id in members:
        return 4

    return -1


async def get_userme(database: Redis, user_id: str):
    cached = await database.get(f"cache:user:{user_id}")
    if cached is not None:
        return msgpack.unpackb(cached)

    access_token = await database.get(f"user:{user_id}:oauth:token")
    if access_token is None:
        raise HTTPException(401, "Session expired")

    print("user cache missed", user_id in get_user_lock and "locked" or "locking")
    if user_id in get_user_lock:
        await get_user_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}")
        if cached is not None:
            return msgpack.unpackb(cached)

    get_user_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(access_token.decode(), "Bearer") as selfbot:
            user = await selfbot.fetch_my_user()

    except UnauthorizedError:
        await database.delete((f"user:{user_id}:oauth:token",))
        raise HTTPException(401, "Session expired")

    finally:
        get_user_lock[user_id].set()
        del get_user_lock[user_id]

    userobj = {
        "id": user.id,
        "name": user.username,
        "discriminator": user.discriminator,
        "avatar": user.avatar_hash,
    }
    await database.set(f"cache:user:{user_id}", msgpack.packb(userobj), ex=30)

    return userobj


limiter = Limiter(key_func=get_visitor_ip, global_limits=("10/s", "50/10s", "100/m"))

reporters: list[ReportFunc] = []

cf_email = os.getenv("cloudflare/email")
cf_key = os.getenv("cloudflare/api-key")
if cf_email is not None and cf_key is not None:
    zone = os.getenv("cloudflare/zone")
    reporters.append(
        CloudflareIPAccessRuleReporter(
            cf_email,
            cf_key,
            zone,
            "Banned for exceeding ratelimits on api.cleanerbot.xyz",
        )
    )

limiter.jail = IPJail(get_visitor_ip, ("50/5m",), reporters)
