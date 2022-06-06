import asyncio
import os
import typing
from datetime import datetime

import hikari
import msgpack  # type: ignore
from cleaner_conf.guild import GuildConfig, GuildEntitlements
from coredis import Redis
from fastapi import Depends, Header, HTTPException, Request
from hikari import Permissions, RESTApp, UnauthorizedError
from httpx import AsyncClient
from jose import jws  # type: ignore
from slowerapi import IPJail, Limiter, get_visitor_ip
from slowerapi.jail import ReportFunc
from slowerapi.reporters.cf import CloudflareIPAccessRuleReporter

from .schemas.types import TAuthObject, TPartialGuildInfo, TUserInfo

home = "https://cleanerbot.xyz"
redis_host = os.getenv("redis/host", "localhost")
redis_passwd = os.getenv("redis/password")
redis = Redis.from_url(f"redis://:{redis_passwd}@{redis_host}:6379")
aclient = AsyncClient(headers={"user-agent": "CleanerBot (cleanerbot.xyz 0.1.0)"})
hikari_rest = RESTApp()


def with_database() -> Redis[bytes]:
    return redis


def with_asyncclient() -> AsyncClient:
    return aclient


async def with_hikari() -> RESTApp:
    return hikari_rest


async def with_auth(
    x_token: str = Header(None), database: Redis[bytes] = Depends(with_database)
) -> str:
    if x_token is None:
        raise HTTPException(401, "Missing X-Token header")

    secret = os.getenv("backend/jwt-secret")
    try:
        data: bytes = jws.verify(x_token, secret, algorithms=["HS256"])
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
    x_token: str = Header(None), database: Redis[bytes] = Depends(with_database)
) -> str | None:
    try:
        return await with_auth(x_token, database)
    except HTTPException:
        return None


async def has_entitlement(
    database: Redis[bytes], guild_id: str | int, entitlement: str
) -> bool:
    raw_value: bytes | None = await database.hget(
        f"guild:{guild_id}:entitlements", entitlement
    )
    value: int
    if raw_value is None:
        value = GuildEntitlements.__fields__[entitlement].default
    else:
        value = msgpack.unpackb(raw_value)

    if value == 0:
        return True

    plan = await database.hget(f"guild:{guild_id}:entitlements", "plan")
    if plan is None:
        return False

    decoded_plan: int = msgpack.unpackb(plan)
    return decoded_plan >= value


async def is_suspended(database: Redis[bytes], guild_id: str | int) -> bool:
    return bool(await get_entitlement(database, guild_id, "suspended"))


async def get_entitlement(
    database: Redis[bytes], guild_id: str | int, name: str
) -> int:
    value = await database.hget(f"guild:{guild_id}:entitlements", name)
    if value is None:
        return GuildEntitlements.__fields__[name].default  # type: ignore
    return getattr(  # type: ignore
        GuildEntitlements(**{name: msgpack.unpackb(value)}), name
    )


async def get_config(
    database: Redis[bytes], guild_id: str | int, name: str
) -> typing.Any:
    value = await database.hget(f"guild:{guild_id}:config", name)
    if value is None:
        return GuildConfig.__fields__[name].default
    return getattr(GuildConfig(**{name: msgpack.unpackb(value)}), name)


async def get_auth_object(database: Redis[bytes], user_id: str) -> TAuthObject:
    raw_auth_object = await database.get(f"user:{user_id}:oauth")
    if raw_auth_object is None:
        raise HTTPException(401, "Session expired")
    auth_object = msgpack.unpackb(raw_auth_object)
    return auth_object  # type: ignore


get_guilds_lock: dict[str, asyncio.Event] = {}
get_user_lock: dict[str, asyncio.Event] = {}


async def get_guilds(database: Redis[bytes], user_id: str) -> list[TPartialGuildInfo]:
    cached = await database.get(f"cache:user:{user_id}:guilds")
    if cached is not None:
        return msgpack.unpackb(cached)  # type: ignore

    auth_object = await get_auth_object(database, user_id)

    print("guild cache missed", user_id in get_guilds_lock and "locked" or "locking")
    if user_id in get_guilds_lock:
        await get_guilds_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}:guilds")
        if cached is not None:
            return msgpack.unpackb(cached)  # type: ignore

    get_guilds_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(auth_object["token"], "Bearer") as selfbot:
            guilds = await selfbot.fetch_my_guilds()

    except UnauthorizedError:
        await database.delete((f"user:{user_id}:oauth",))
        raise HTTPException(401, "Session expired")

    finally:
        get_guilds_lock[user_id].set()
        del get_guilds_lock[user_id]

    guildobj: list[TPartialGuildInfo] = [
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


async def get_access_type(
    database: Redis[bytes], guild: hikari.OwnGuild, user_id: str
) -> int:
    if guild.is_owner:
        return 0
    permissions = await get_config(database, guild.id, "access_permissions")
    if permissions and guild.my_permissions & Permissions.ADMINISTRATOR:
        return 1
    elif permissions == 2 and guild.my_permissions & Permissions.MANAGE_GUILD:
        return 2

    # TODO: roles

    members = await get_config(database, guild.id, "access_members")
    if members is not None and user_id in members:
        return 4

    return -1


async def get_userme(database: Redis[bytes], user_id: str) -> TUserInfo:
    cached = await database.get(f"cache:user:{user_id}")
    if cached is not None:
        return msgpack.unpackb(cached)  # type: ignore

    auth_object = await get_auth_object(database, user_id)

    print("user cache missed", user_id in get_user_lock and "locked" or "locking")
    if user_id in get_user_lock:
        await get_user_lock[user_id].wait()
        cached = await database.get(f"cache:user:{user_id}")
        if cached is not None:
            return msgpack.unpackb(cached)  # type: ignore

    get_user_lock[user_id] = asyncio.Event()
    try:
        async with hikari_rest.acquire(auth_object["token"], "Bearer") as selfbot:
            user = await selfbot.fetch_my_user()

    except UnauthorizedError:
        await database.delete((f"user:{user_id}:oauth",))
        raise HTTPException(401, "Session expired")

    finally:
        get_user_lock[user_id].set()
        del get_user_lock[user_id]

    userobj: TUserInfo = {
        "id": str(user.id),
        "name": user.username,
        "discriminator": user.discriminator,
        "avatar": user.avatar_hash,
    }
    await database.set(f"cache:user:{user_id}", msgpack.packb(userobj), ex=30)

    return userobj


async def verify_captcha(token: str) -> None:
    hcaptcha_secret = os.getenv("hcaptcha/secret")
    hcaptcha_sitekey = os.getenv("hcaptcha/sitekey")
    if hcaptcha_secret is None or hcaptcha_sitekey is None:
        raise HTTPException(500, "Configuration issue, please contact support")
    res = await aclient.post(
        "https://hcaptcha.com/siteverify",
        data={
            "secret": hcaptcha_secret,
            "sitekey": hcaptcha_sitekey,
            "response": token,
        },
    )
    data = res.json()
    if not data["success"]:
        raise HTTPException(400, "Invalid captcha token")


async def print_request(request: Request) -> bytes:
    print(request.method, str(request.url))
    for header, value in request.headers.items():
        print(f"{header}: {value}")
    print()
    body = await request.body()
    try:
        print(body.decode())
    except UnicodeDecodeError:
        print(body)
    return body


limiter = Limiter(key_func=get_visitor_ip, global_limits=("10/s", "50/10s", "100/m"))

reporters: list[ReportFunc] = []

cf_token = os.getenv("cloudflare/api-token")
if cf_token is not None:
    zone = os.getenv("cloudflare/zone")
    reporters.append(
        CloudflareIPAccessRuleReporter(
            cf_token,
            zone_id=zone,
            note="Banned for exceeding ratelimits on api.cleanerbot.xyz",
        )
    )

limiter.jail = IPJail(get_visitor_ip, ("50/5m",), reporters)
