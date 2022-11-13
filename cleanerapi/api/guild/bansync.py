import string
import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic.response import empty
from sanic_ext import openapi

from ...helpers.settings import (
    get_config_field,
    validate_boolean,
    validate_snowflake,
    get_entitlement_field,
)
from ...helpers.snowflake import generate_snowflake
from ...helpers.rpc import rpc_call

bp = Blueprint("BanSync", version=1)


@bp.get("/guild/<guild:int>/bansync")
@openapi.summary("returns a list of all your own ban lists")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_bansync_lists(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    banlists = await database.smembers(f"guild:{guild}:bansync:lists")
    data: list[dict[str, list[str] | str | None | bool | int]] = []
    for raw_id in banlists:
        name, auto_sync, owner, managers = await database.hmget(
            f"bansync:banlist:{raw_id.decode()}",
            ("name", "auto_sync", "owner", "managers"),
        )
        data.append(
            {
                "id": raw_id.decode(),
                "name": name.decode() if name else "untitled list",
                "count": await database.scard(
                    f"bansync:banlist:{raw_id.decode()}:users"
                ),
                "auto_sync": (
                    str(guild) in auto_sync.decode().split(",") if auto_sync else False
                ),
                "managers": (
                    None
                    if not owner or owner.decode() != str(guild)
                    else (managers.decode().split(",") if managers else [])
                ),
                "owner": owner.decode() if owner else None,
            }
        )
    return json(data)


@bp.post("/guild/<guild:int>/bansync")
@openapi.summary("create a new banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def create_bansync_list(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    limit = await get_entitlement_field(database, guild, "bansync_own_limit")
    if await database.scard(f"guild:{guild}:bansync:lists") >= limit:
        return text("Bansync list limit reached", 400)

    list_id = generate_snowflake()
    await database.sadd(f"guild:{guild}:bansync:lists", (list_id,))
    await database.hset(
        f"bansync:banlist:{list_id}",
        {
            "owner": guild,
        },
    )
    return json(
        {
            "id": str(list_id),
            "name": "untitled list",
            "count": 0,
            "auto_sync": "",
            "managers": [],
            "owner": str(guild),
        }
    )


@bp.patch("/guild/<guild:int>/bansync/<banlist:int>")
@openapi.summary("patch ban list settings")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def patch_bansync_list(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)

    body = request.json
    auto_sync, owner, name, managers = await database.hmget(
        f"bansync:banlist:{banlist}", ("auto_sync", "owner", "name", "managers")
    )

    if "auto_sync" in body:
        if not validate_boolean(body["auto_sync"]):
            return text("'auto_sync' must be a valid boolean")

    if "name" in body:
        if owner is None or owner.decode() != str(guild):
            return text("must be owner of the ban list to change the name", 403)

        allowed_characters = string.ascii_letters + string.digits + " _-[]()"
        if (
            not isinstance(body["name"], str)
            or not all(x in allowed_characters for x in body["name"])
            or not 64 >= len(body["name"]) >= 6
        ):
            return text(
                f"'name' must be between 6 and 64 character and only contain {allowed_characters!r}",
                400,
            )

    sync_set = set(auto_sync.decode().split(",")) if auto_sync else set()
    changes: dict[str, str] = {}

    if "auto_sync" in body:
        if body["auto_sync"]:
            sync_set.add(str(guild))
        else:
            sync_set.remove(str(guild))
        changes["auto_sync"] = ",".join(sync_set)

    if "name" in body:
        changes["name"] = body["name"]

    if changes:
        await database.hset(f"bansync:banlist:{banlist}", changes)

    return json(
        {
            "id": str(banlist),
            "name": name.decode() if name else "untitled list",
            "count": await database.scard(f"bansync:banlist:{banlist}:users"),
            "auto_sync": str(guild) in sync_set,
            "managers": (
                None
                if not owner or owner.decode() != str(guild)
                else (managers.decode().split(",") if managers else [])
            ),
            "owner": owner.decode() if owner else None,
        }
    )


@bp.delete("/guild/<guild:int>/bansync/<banlist:int>")
@openapi.summary("delete ban list")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_bansync_list(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    owner, current_managers_raw = await database.hmget(
        f"bansync:banlist:{banlist}", ("owner", "managers")
    )
    if owner is None or owner.decode() != str(guild):
        return text("Not owner of this ban list", 403)

    await database.delete((f"bansync:banlist:{banlist}",))
    await database.srem(f"guild:{guild}:bansync:lists", (banlist,))

    current_managers = (
        set(current_managers_raw.decode().split(",")) if current_managers_raw else set()
    )
    for managing_guild in current_managers:
        await database.srem(f"guild:{managing_guild}:bansync:lists", (banlist,))

    return empty()


@bp.post("/guild/<guild:int>/bansync/<banlist:int>/import")
@openapi.summary("import server bans into banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_bansync_import(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)

    result = await rpc_call(
        database,
        "bansync:import",
        guild,
        banlist,
    )
    if not result["ok"]:
        return text(result["message"], 409)
    return json(result["data"])


@bp.get("/guild/<guild:int>/bansync/<banlist:int>/users")
@openapi.summary("get all users of the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    return json(
        [
            id.decode()
            for id in await database.smembers(f"bansync:banlist:{banlist}:users")
        ]
    )


@bp.post("/guild/<guild:int>/bansync/<banlist:int>/users")
@openapi.summary("add new users to the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    ids = [id for id in ids if validate_snowflake(id)]
    limit = await get_entitlement_field(database, guild, "bansync_user_limit")
    currently_used = await database.scard(f"bansync:banlist:{banlist}:users")
    ids = ids[: limit - currently_used]

    if ids:
        return json(
            await database.sadd(
                f"bansync:banlist:{banlist}:users",
                typing.cast(list[str | int | bytes | float], ids),
            )
        )
    return json(0)


@bp.delete("/guild/<guild:int>/bansync/<banlist:int>/users", ignore_body=False)
@openapi.summary("delete users from the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    ids = [id for id in ids if validate_snowflake(id)]

    if ids:
        return json(
            await database.srem(
                f"bansync:banlist:{banlist}:users",
                typing.cast(list[str | int | bytes | float], ids),
            )
        )
    return json(0)


@bp.put("/guild/<guild:int>/bansync/<banlist:int>/users")
@openapi.summary("overwrite banlist with new users")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def put_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    ids = [id for id in ids if validate_snowflake(id)]
    limit = await get_entitlement_field(database, guild, "bansync_user_limit")
    ids = ids[:limit]

    await database.delete((f"bansync:banlist:{banlist}:users",))
    if ids:
        return json(
            await database.sadd(
                f"bansync:banlist:{banlist}:users",
                typing.cast(list[str | int | bytes | float], ids),
            )
        )
    return json(0)


@bp.put("/guild/<guild:int>/bansync/<banlist:int>/managers")
@openapi.summary("overwrite banlist managers with new guild ids")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def put_bansync_managers(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(f"guild:{guild}:bansync:lists", banlist):
        return text("Banlist not found", 404)
    owner, current_managers_raw = await database.hmget(
        f"bansync:banlist:{banlist}", ("owner", "managers")
    )
    if owner is None or owner.decode() != str(guild):
        return text("Not owner of this ban list", 403)
    ids = typing.cast(set[str], set(request.json))
    ids = {id for id in ids if validate_snowflake(id)}
    ids.discard(str(guild))

    if len(ids) > 100:
        return text("Cannot have over 100 managing guilds.", 400)

    current_managers: set[str] = (
        set(current_managers_raw.decode().split(",")) if current_managers_raw else set()
    )

    for removed_guild in current_managers - ids:
        await database.srem(f"guild:{removed_guild}:bansync:lists", (banlist,))

    for added_guild in ids - current_managers:
        subscribed_banlists = await get_config_field(
            database, added_guild, "bansync_subscribed"
        )
        if str(banlist) in subscribed_banlists:
            await database.sadd(f"guild:{added_guild}:bansync:lists", (banlist,))
        else:
            ids.remove(added_guild)

    await database.hset(f"bansync:banlist:{banlist}", {"managers": ",".join(ids)})

    return json(list(ids))
