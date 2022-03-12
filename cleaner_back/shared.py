import asyncio
import json
from datetime import datetime
import os
from typing import Union

from coredis import StrictRedis  # type: ignore
from fastapi import Depends, HTTPException, Header
from hikari import RESTApp, Permissions, UnauthorizedError
from httpx import AsyncClient
from jose import jws  # type: ignore

from cleaner_conf import entitlements
from cleaner_ratelimit import Limiter, get_visitor_ip
from cleaner_ratelimit.jail import Jail, CloudflareIPAccessRuleReporter


home = "http://localhost:3000"
redis = StrictRedis()
aclient = AsyncClient(headers={"user-agent": "CleanerBot (cleaner.leodev.xyz 0.1.0)"})
hikari_rest = RESTApp()


def with_database() -> StrictRedis:
    return redis


def with_asyncclient() -> AsyncClient:
    return aclient


async def with_hikari(database: StrictRedis = Depends(with_database)):
    token = await database.get(os.getenv("SECRET_BOT_TOKEN"))
    async with hikari_rest.acquire(token, "Bot") as restimpl:
        yield restimpl


async def with_auth(
    x_token: str = Header(None),
    database: StrictRedis = Depends(with_database),
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

    session_exists = await database.exists(f"user:{userid}:dash:session:{session}")
    if not session_exists:
        raise HTTPException(401, "Session revoked")

    return userid


async def with_optional_auth(
    x_token: str = Header(None),
    database: StrictRedis = Depends(with_database),
):
    try:
        return await with_auth(x_token, database)
    except HTTPException:
        return None


def is_developer(user_id: Union[int, str]) -> bool:
    if isinstance(user_id, str):
        user_id = int(user_id)
    return user_id in (633993042755452932, 918875640046964797, 922118393178517545)


async def has_entitlement(database: StrictRedis, guild: str, entitlement: str) -> bool:
    value = await database.get(f"guild:{guild}:entitlement:{entitlement}")
    if value is None:
        value = entitlements[entitlement].default
    else:
        value = int(value)

    if value == 0:
        return True

    plan = await database.get(f"guild:{guild}:entitlement:plan")
    if plan is None:
        return False

    return int(plan) >= value


get_guilds_lock: dict[str, asyncio.Event] = {}
get_user_lock: dict[str, asyncio.Event] = {}


async def get_guilds(database: StrictRedis, user_id: str):
    cached = await database.get(f"cache:user:{user_id}:guilds")
    if cached is not None:
        return json.loads(cached.decode())

    access_token = await database.get(f"user:{user_id}:oauth:token")
    if access_token is None:
        raise HTTPException(401, "Session expired")

    print("guild cache missed", user_id in get_guilds_lock and "locked" or "locking")
    if user_id in get_guilds_lock:
        await get_guilds_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}:guilds")
        if cached is not None:
            return json.loads(cached.decode())

    get_guilds_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(access_token.decode(), "Bearer") as selfbot:
            guilds = await selfbot.fetch_my_guilds()

    except UnauthorizedError:
        await database.delete(f"user:{user_id}:oauth:token")
        raise HTTPException(401, "Session expired")

    finally:
        get_guilds_lock[user_id].set()
        del get_guilds_lock[user_id]

    required_permissions = Permissions.ADMINISTRATOR | Permissions.MANAGE_GUILD
    guildobj = [
        {
            "id": str(guild.id),
            "name": guild.name,
            "icon": guild.make_icon_url(ext="webp", size=64).url  # type: ignore
            if guild.icon_hash
            else None,
            "is_owner": guild.is_owner,
            "is_admin": guild.my_permissions & Permissions.ADMINISTRATOR > 0,
        }
        for guild in guilds
        if guild.my_permissions & required_permissions
    ]

    await database.set(f"cache:user:{user_id}:guilds", json.dumps(guildobj), ex=30)

    return guildobj


async def get_userme(database: StrictRedis, user_id: str):
    cached = await database.get(f"cache:user:{user_id}")
    if cached is not None:
        return json.loads(cached.decode())

    access_token = await database.get(f"user:{user_id}:oauth:token")
    if access_token is None:
        raise HTTPException(401, "Session expired")

    print("user cache missed", user_id in get_user_lock and "locked" or "locking")
    if user_id in get_user_lock:
        await get_user_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}")
        if cached is not None:
            return json.loads(cached.decode())

    get_user_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(access_token.decode(), "Bearer") as selfbot:
            user = await selfbot.fetch_my_user()

    except UnauthorizedError:
        await database.delete(f"user:{user_id}:oauth:token")
        raise HTTPException(401, "Session expired")

    finally:
        get_user_lock[user_id].set()
        del get_user_lock[user_id]

    userobj = {
        "id": user.id,
        "name": user.username,
        "avatar": user.make_avatar_url(ext="webp", size=64).url  # type: ignore
        if user.avatar_hash is not None
        else None,
    }
    await database.set(f"cache:user:{user_id}", json.dumps(userobj), ex=30)

    return userobj


limiter = Limiter(key_func=get_visitor_ip, global_limits=["10/s", "50/10s", "100/m"])

reporter = None

if (cf_email := os.getenv("SECRET_CF_EMAIL")) and (
    cf_token := os.getenv("SECRET_CF_TOKEN")
):
    zone = os.getenv("SECRET_CF_ZONE")
    reporter = CloudflareIPAccessRuleReporter(
        cf_email,
        cf_token,
        zone,
        "Banned for exceeding ratelimits on cleaner.leodev.xyz/api",
    )

limiter.jail = Jail(get_visitor_ip, "50/1m", reporter)
