import string
import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic.response import empty
from sanic_ext import openapi

from ...helpers.bansync import (
    BANLIST_LIMIT,
    UNTITLED_FALLBACK,
    add_users,
    get_users,
    put_users,
    remove_users,
)
from ...helpers.settings import validate_snowflakes
from ...helpers.snowflake import generate_snowflake

bp = Blueprint("UserBansync", version=1)


@bp.get("/user/me/bansync/banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json": dict}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_user_me_banlists(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    banlists = await database.smembers(
        f"user:{request.ctx.user_token.user_id}:bansync:banlists"
    )
    data = []
    for raw_id in banlists:
        name, managers = await database.hmget(
            f"bansync:banlist:{raw_id.decode()}", ("name", "managers")
        )
        data.append(
            {
                "id": raw_id.decode(),
                "name": name.decode() if name else UNTITLED_FALLBACK,
                "count": await database.scard(
                    f"bansync:banlist:{raw_id.decode()}:users"
                ),
                "managers": managers.decode().split(",") if managers else [],
            }
        )

    return json(data)


@bp.post("/user/me/bansync")
@openapi.summary("create a new banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def create_bansync_list(request: Request, database: Redis[bytes]) -> HTTPResponse:
    if (
        await database.scard(f"user:{request.ctx.user_token.user_id}:bansync:lists")
        >= BANLIST_LIMIT
    ):
        return text("Bansync list limit reached", 400)

    list_id = generate_snowflake()
    await database.hset(
        f"bansync:banlist:{list_id}",
        {
            "owner": request.ctx.user_token.user_id,
        },
    )
    await database.sadd(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", (list_id,)
    )

    return json(
        {
            "id": str(list_id),
            "name": UNTITLED_FALLBACK,
            "count": 0,
            "managers": [],
        }
    )


@bp.delete("/user/me/bansync/<banlist:int>")
@openapi.summary("delete ban list")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_bansync_list(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.srem(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", (banlist,)
    ):
        return text("Banlist not found", 404)

    await database.delete((f"bansync:banlist:{banlist}",))

    return empty()


@bp.patch("/user/me/bansync/<banlist:int>")
@openapi.summary("patch ban list settings")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def patch_bansync_list(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", banlist
    ):
        return text("Banlist not found", 404)

    body = request.json
    name, managers = await database.hmget(
        f"bansync:banlist:{banlist}", ("name", "managers")
    )

    if "name" in body:
        allowed_characters = string.ascii_letters + string.digits + " _-[]()"
        if (
            not isinstance(body["name"], str)
            or not all(x in allowed_characters for x in body["name"])
            or not 64 >= len(body["name"]) >= 6
        ):
            return text(
                r"'name' must match /^[\W-\[\]()]{4,64}$/",
                400,
            )

    if "managers" in body:
        if not validate_snowflakes(body["managers"]):
            return text("'managers' must only contain snowflakes", 400)
        elif len(body["managers"]) > 100:
            return text("'managers' cannot contain more than 100 entries")

    changes: dict[str | bytes, str | bytes | int | float] = {}

    if "name" in body:
        changes["name"] = body["name"]

    if "managers" in body:
        changes["managers"] = ",".join(body["managers"])

    if changes:
        await database.hset(f"bansync:banlist:{banlist}", changes)

    return json(
        {
            "id": str(banlist),
            "name": name.decode() if name else "untitled list",
            "count": await database.scard(f"bansync:banlist:{banlist}:users"),
            "managers": managers.decode().split(",") if managers else [],
        }
    )


@bp.get("/user/me/bansync/<banlist:int>/users")
@openapi.summary("get all users of the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_bansync_user_bans(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", banlist
    ):
        return text("Banlist not found", 404)
    return json(get_users(database, banlist))


@bp.post("/user/me/bansync/<banlist:int>/users")
@openapi.summary("add new users to the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_bansync_user_bans(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", banlist
    ):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await add_users(database, banlist, ids))


@bp.delete("/user/me/bansync/<banlist:int>/users", ignore_body=False)
@openapi.summary("delete users from the banlist")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_bansync_user_bans(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", banlist
    ):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await remove_users(database, banlist, ids))


@bp.put("/user/me/bansync/<banlist:int>/users")
@openapi.summary("overwrite banlist with new users")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(404, {"text/plain": str}, "Banlist not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def put_bansync_user_bans(
    request: Request, banlist: int, database: Redis[bytes]
) -> HTTPResponse:
    if not await database.sismember(
        f"user:{request.ctx.user_token.user_id}:bansync:lists", banlist
    ):
        return text("Banlist not found", 404)
    ids = typing.cast(list[str], request.json)
    return json(await put_users(database, banlist, ids))
