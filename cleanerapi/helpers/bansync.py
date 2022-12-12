import typing

from coredis import Redis

from .settings import validate_snowflake

UNTITLED_FALLBACK = "untitled"
USER_LIMIT = 50_000
BANLIST_LIMIT = 5


async def get_users(database: Redis[bytes], banlist: int) -> list[str]:
    return [
        id.decode()
        for id in await database.smembers(f"bansync:banlist:{banlist}:users")
    ]


async def add_users(database: Redis[bytes], banlist: int, users: list[str]) -> int:
    ids = [id for id in users if validate_snowflake(id)]
    currently_used = await database.scard(f"bansync:banlist:{banlist}:users")
    ids = ids[: USER_LIMIT - currently_used]

    if not ids:
        return 0
    return await database.sadd(
        f"bansync:banlist:{banlist}:users",
        typing.cast(list[str | int | bytes | float], ids),
    )


async def remove_users(database: Redis[bytes], banlist: int, users: list[str]) -> int:
    ids = [id for id in users if validate_snowflake(id)]

    if not ids:
        return 0
    return await database.srem(
        f"bansync:banlist:{banlist}:users",
        typing.cast(list[str | int | bytes | float], ids),
    )


async def put_users(database: Redis[bytes], banlist: int, users: list[str]) -> int:
    ids = [id for id in users if validate_snowflake(id)]
    ids = ids[:USER_LIMIT]

    await database.delete((f"bansync:banlist:{banlist}:users",))
    if not ids:
        return 0
    return await database.sadd(
        f"bansync:banlist:{banlist}:users",
        typing.cast(list[str | int | bytes | float], ids),
    )
