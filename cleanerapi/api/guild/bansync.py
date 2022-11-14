import string
import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic_ext import openapi

from ...helpers.bansync import (
    UNTITLED_FALLBACK,
    add_users,
    get_users,
    put_users,
    remove_users,
)
from ...helpers.rpc import rpc_call
from ...helpers.settings import get_config_field, validate_boolean

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
    banlists = await get_config_field(database, guild, "bansync_subscribed")
    data: list[dict[str, list[str] | str | None | bool | int]] = []
    for raw_id in banlists:
        name, owner, auto_sync, managers = await database.hmget(
            f"bansync:banlist:{raw_id.decode()}",
            ("name", "owner", "auto_sync", "managers"),
        )
        if owner is None:
            data.append({"id": raw_id.decode(), "deleted": True})
        else:
            data.append(
                {
                    "id": raw_id.decode(),
                    "name": name.decode() if name else UNTITLED_FALLBACK,
                    "count": await database.scard(
                        f"bansync:banlist:{raw_id.decode()}:users"
                    ),
                    "auto_sync": (
                        str(guild) in auto_sync.decode().split(",")
                        if auto_sync
                        else False
                    ),
                    "manager": (
                        str(guild) in (managers.decode().split(",") if managers else [])
                    ),
                }
            )
    return json(data)


@bp.patch("/guild/<guild:int>/bansync/<banlist:int>")
@openapi.summary("patch ban list settings")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def patch_bansync_list(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
        return text("Banlist not found", 404)

    body = request.json
    auto_sync, name = await database.hmget(
        f"bansync:banlist:{banlist}", ("auto_sync", "name")
    )

    if "auto_sync" in body:
        if not validate_boolean(body["auto_sync"]):
            return text("'auto_sync' must be a valid boolean")

    sync_set = set(auto_sync.decode().split(",")) if auto_sync else set()
    changes: dict[str | bytes, str | bytes | int | float] = {}

    if "auto_sync" in body:
        if body["auto_sync"]:
            sync_set.add(str(guild))
        else:
            sync_set.remove(str(guild))
        changes["auto_sync"] = ",".join(sync_set)

    if changes:
        await database.hset(f"bansync:banlist:{banlist}", changes)

    return json(
        {
            "id": str(banlist),
            "name": name.decode() if name else UNTITLED_FALLBACK,
            "count": await database.scard(f"bansync:banlist:{banlist}:users"),
            "auto_sync": str(guild) in sync_set,
        }
    )


@bp.post("/guild/<guild:int>/bansync/<banlist:int>/import")
@openapi.summary("import server bans into banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_bansync_import(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
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
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
        return text("Banlist not found", 404)
    return json(await get_users(database, banlist))


@bp.post("/guild/<guild:int>/bansync/<banlist:int>/users")
@openapi.summary("add new users to the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await add_users(database, banlist, ids))


@bp.delete("/guild/<guild:int>/bansync/<banlist:int>/users", ignore_body=False)
@openapi.summary("delete users from the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await remove_users(database, banlist, ids))


@bp.put("/guild/<guild:int>/bansync/<banlist:int>/users")
@openapi.summary("overwrite banlist with new users")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild or banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def put_bansync_user_bans(
    request: Request, guild: int, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    managers = await database.hget(f"bansync:banlist:{banlist}", "managers")
    if managers is None or str(guild) not in managers.decode().split(","):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await put_users(database, banlist, ids))
