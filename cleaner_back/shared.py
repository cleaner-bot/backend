import asyncio
import os
from datetime import datetime

import msgpack  # type: ignore
from cleaner_conf.guild import GuildConfig, GuildEntitlements
from cleaner_ratelimit import Limiter, get_visitor_ip
from cleaner_ratelimit.jail import CloudflareIPAccessRuleReporter, Jail
from coredis import StrictRedis
from fastapi import Depends, Header, HTTPException
from hikari import Permissions, RESTApp, UnauthorizedError
from httpx import AsyncClient
from jose import jws  # type: ignore

home = "https://cleanerbot.xyz"
redis_db = os.getenv("REDIS_URL")
redis = StrictRedis.from_url(redis_db) if redis_db is not None else StrictRedis()
aclient = AsyncClient(headers={"user-agent": "CleanerBot (cleanerbot.xyz 0.1.0)"})
hikari_rest = RESTApp()


def with_database() -> StrictRedis:
    return redis


def with_asyncclient() -> AsyncClient:
    return aclient


async def with_hikari():
    token = os.getenv("SECRET_BOT_TOKEN")
    async with hikari_rest.acquire(token, "Bot") as restimpl:
        yield restimpl


async def with_auth(
    x_token: str = Header(None), database: StrictRedis = Depends(with_database)
):
    if x_token is None:
        raise HTTPException(401, "Missing X-Token header")

    secret = os.getenv("SECRET_WEB_AUTH")
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
    x_token: str = Header(None), database: StrictRedis = Depends(with_database)
):
    try:
        return await with_auth(x_token, database)
    except HTTPException:
        return None


async def has_entitlement(
    database: StrictRedis, guild_id: str | int, entitlement: str
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


async def is_suspended(database: StrictRedis, guild_id: str | int) -> bool:
    return await get_entitlement(database, guild_id, "suspended")


async def get_entitlement(
    database: StrictRedis, guild_id: str | int, name: str
) -> bool:
    value = await database.hget(f"guild:{guild_id}:entitlements", name)
    if value is None:
        return GuildEntitlements.__fields__[name].default
    return GuildEntitlements(suspended=msgpack.unpackb(value)).suspended


async def get_config(database: StrictRedis, guild_id: str | int, name: str):
    value = await database.hget(f"guild:{guild_id}:config", name)
    if value is None:
        return GuildConfig.__fields__[name].default
    return getattr(GuildConfig(**{name: msgpack.unpackb(value)}), name)


get_guilds_lock: dict[str, asyncio.Event] = {}
get_user_lock: dict[str, asyncio.Event] = {}


async def get_guilds(database: StrictRedis, user_id: str):
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

    required_permissions = Permissions.ADMINISTRATOR | Permissions.MANAGE_GUILD
    guildobj = [
        {
            "id": str(guild.id),
            "name": guild.name,
            "icon": guild.icon_hash,
            "is_owner": guild.is_owner,
            "is_admin": guild.my_permissions & Permissions.ADMINISTRATOR > 0,
        }
        for guild in guilds
        if guild.my_permissions & required_permissions
    ]

    await database.set(f"cache:user:{user_id}:guilds", msgpack.packb(guildobj), ex=30)

    return guildobj


async def get_userme(database: StrictRedis, user_id: str):
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


limiter = Limiter(key_func=get_visitor_ip, global_limits=["10/s", "50/10s", "100/m"])

reporter = None

cf_email = os.getenv("SECRET_CF_EMAIL")
cf_key = os.getenv("SECRET_CF_KEY")
if cf_email is not None and cf_key is not None:
    zone = os.getenv("CF_ZONE")
    reporter = CloudflareIPAccessRuleReporter(
        cf_email,
        cf_key,
        zone,
        "Banned for exceeding ratelimits on api.cleanerbot.xyz",
    )

limiter.jail = Jail(get_visitor_ip, "50/5m", reporter)
