from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json
from sanic.response import empty
from sanic_ext import openapi

bp = Blueprint("LinkFilter", version=1)


@bp.get("/guild/<guild:int>/linkfilter")
@openapi.summary("returns a dictionary with all whitelisted and blacklisted urls")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_linkfilter_urls(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    whitelist = [
        x.decode()
        for x in await database.lrange(f"guild:{guild}:linkfilter:whitelist", 0, -1)
    ]
    blacklist = [
        x.decode()
        for x in await database.lrange(f"guild:{guild}:linkfilter:blacklist", 0, -1)
    ]
    return json({"whitelist": whitelist, "blacklist": blacklist})


@bp.patch("/guild/<guild:int>/linkfilter")
@openapi.summary("overwrites the linkfilteer")
@openapi.secured("user")
@openapi.response(204, None, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def patch_linkfilter_urls(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    for name in ("whitelist", "blacklist"):
        lst = request.json.get(name)
        if not isinstance(lst, list):
            continue
        lst = [
            x.strip().strip(" /")
            for x in lst
            if isinstance(x, str) and 128 >= len(x) > 2
        ][:10_000]
        await database.delete((f"guild:{guild}:linkfilter:{name}",))
        await database.rpush(f"guild:{guild}:linkfilter:{name}", tuple(lst))
    return empty()
