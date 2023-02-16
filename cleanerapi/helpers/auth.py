from __future__ import annotations

import base64
import hmac
import struct
import typing
from datetime import datetime

import hikari
import msgpack  # type: ignore
from coredis import Redis
from hikari.internal.time import utc_datetime
from sanic import Request
from sanic.exceptions import SanicException

from ..security.fingerprint import fingerprint
from .lock import named_locks
from .settings import get_config_field

UserTokenStructHeader = struct.Struct(">QQQH6s")


class UserToken(typing.NamedTuple):
    user_id: int  # 64bit int
    timestamp: int  # 64bit int
    session_id: int  # 64bit int
    mfa_timestamp: int  # 16bit int (in minutes)
    browser_fingerprint: bytes  # 6 bytes

    def is_mfa_valid(self) -> bool:
        if self.mfa_timestamp == 0:
            return False
        now = utc_datetime().timestamp()
        return now <= self.timestamp + self.mfa_timestamp * 60

    def is_fingerprint_valid(self, request: Request) -> bool:
        expected_fingerprint = fingerprint(request, "user")[:6]
        return hmac.compare_digest(self.browser_fingerprint, expected_fingerprint)


async def parse_user_token(
    request: Request, database: Redis[bytes]
) -> UserToken | None:
    if request.token is None:
        return None

    try:
        token = base64.urlsafe_b64decode(request.token + "=" * (len(request.token) % 4))
    except ValueError:
        return None

    if len(token) != UserTokenStructHeader.size + 32:
        return None
    elif not hmac.compare_digest(
        hmac.digest(
            bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET), token[:-32], "sha256"
        ),
        token[-32:],
    ):
        return None

    user_token = UserToken(*UserTokenStructHeader.unpack(token[:-32]))

    authtoken, all_invalid_before = await database.hmget(
        f"user:{user_token.user_id}:oauth2", ("token", "revoked")
    )
    if authtoken is None:
        return None
    elif (
        all_invalid_before is not None
        and int(all_invalid_before) > user_token.timestamp
    ):
        return None
    elif datetime.utcnow().timestamp() - 7 * 60 * 60 * 24 > user_token.timestamp:
        return None

    return user_token


def create_user_token(request: Request, user_token: UserToken) -> str:
    header = UserTokenStructHeader.pack(*user_token)
    checksum = hmac.new(
        bytes.fromhex(request.app.config.BACKEND_AUTH_SECRET), header, "sha256"
    ).digest()
    return base64.urlsafe_b64encode(header + checksum).decode().strip("=")


async def get_user(request: Request, database: Redis[bytes]) -> UserInfo:
    user_id = typing.cast(int, request.ctx.user_token.user_id)
    hikari_rest = typing.cast(hikari.RESTApp, request.app.ctx.hikari_rest)
    async with named_locks[f"user:{user_id}"]:
        cached = await database.get(f"cache:user:{user_id}")
        if cached:
            return typing.cast(UserInfo, msgpack.unpackb(cached))

        token = await database.hget(f"user:{user_id}:oauth2", "token")
        if token is None:
            raise SanicException("Unauthorized", 401)

        try:
            async with hikari_rest.acquire(token.decode(), "Bearer") as selfbot:
                user = await selfbot.fetch_my_user()

        except hikari.UnauthorizedError:
            await database.delete((f"user:{user_id}:oauth2",))
            raise SanicException("Unauthorized", 401)

        flags = []
        if user.is_mfa_enabled:
            flags.append("discord:mfa")
        user_object: UserInfo = {
            "id": str(user.id),
            "name": user.username,
            "discriminator": user.discriminator,
            "avatar": user.avatar_hash or "",
            "flags": flags,
        }
        await database.set(f"cache:user:{user.id}", msgpack.packb(user_object))
        await database.expire(f"cache:user:{user.id}", 30)
        return user_object


async def get_user_guilds(
    request: Request, database: Redis[bytes]
) -> tuple[PartialGuildInfo, ...]:
    user_id = typing.cast(int, request.ctx.user_token.user_id)
    hikari_rest = typing.cast(hikari.RESTApp, request.app.ctx.hikari_rest)
    async with named_locks[f"guilds:{user_id}"]:
        cached = await database.get(f"cache:user:{user_id}:guilds")
        if cached is not None:
            return typing.cast(
                tuple[PartialGuildInfo, ...], msgpack.unpackb(cached, use_list=False)
            )

        token = await database.hget(f"user:{user_id}:oauth2", "token")
        if token is None:
            raise SanicException("Unauthorized", 401)

        try:
            async with hikari_rest.acquire(token.decode(), "Bearer") as selfbot:
                guilds = await selfbot.fetch_my_guilds()

        except hikari.UnauthorizedError:
            await database.delete((f"user:{user_id}:oauth2",))
            raise SanicException("Unauthorized", 401)

        guild_objects: tuple[PartialGuildInfo, ...] = tuple(
            [
                {
                    "id": str(guild.id),
                    "name": guild.name,
                    "icon": guild.icon_hash or "",
                    "access_type": await get_access_type(database, guild, str(user_id)),
                }
                for guild in guilds
            ]
        )
        await database.set(f"cache:user:{user_id}:guilds", msgpack.packb(guild_objects))
        await database.expire(f"cache:user:{user_id}:guilds", 30)
        return guild_objects


async def get_access_type(
    database: Redis[bytes], guild: hikari.OwnGuild, user_id: str
) -> int:
    if guild.is_owner:
        return 0
    permissions = await get_config_field(database, guild.id, "access_permissions")
    if permissions and guild.my_permissions & hikari.Permissions.ADMINISTRATOR:
        return 1
    elif permissions == 2 and guild.my_permissions & hikari.Permissions.MANAGE_GUILD:
        return 2

    # TODO: roles

    members = await get_config_field(database, guild.id, "access_members")
    if members is not None and user_id in members:
        return 4

    return -1


class PartialGuildInfo(typing.TypedDict):
    id: str
    name: str
    icon: str
    access_type: int


class UserInfo(typing.TypedDict):
    id: str
    name: str
    discriminator: str
    avatar: str
    flags: list[str]


DEVELOPERS = {633993042755452932, 647558454491480064}


def is_developer(user_id: int) -> bool:
    return user_id in DEVELOPERS
