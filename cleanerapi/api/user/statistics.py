import typing

import msgpack  # type: ignore
from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic_ext import openapi

from ...helpers.auth import get_user_guilds
from ...helpers.rpc import rpc_call

bp = Blueprint("UserStatistics", version=1)


@bp.get("/user/me/statistics")
@openapi.secured("user")
@openapi.response(200, {"application/json": {}}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
async def get_user_me_statistics(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    guilds = typing.cast(
        dict[int, dict[str, str | bool]],
        {
            int(x["id"]): x
            for x in await get_user_guilds(request, database)
            if x["access_type"] >= 0
        },
    )
    added_guild_ids = await rpc_call(database, "dash:guild-check", tuple(guilds.keys()))
    if not added_guild_ids["ok"]:
        return text(added_guild_ids["message"], 503)

    guild_ids = typing.cast(list[int], added_guild_ids["data"])
    if not guild_ids:
        return json(None)

    statistics: None | dict[str, dict[str, dict[str, dict[str, int]]]] = None
    for guild in guild_ids:
        stats = await database.get(f"guild:{guild}:statistics")
        if stats is None:
            continue
        elif statistics is None:
            statistics = msgpack.unpackb(stats)
        else:
            data = msgpack.unpackb(stats)
            for timespan, stat in data.items():
                if timespan not in statistics:
                    statistics[timespan] = {}
                for key, value in stat.items():
                    if key not in statistics[timespan]:
                        statistics[timespan][key] = {}
                    for key2, value2 in value.items():
                        if key2 in statistics[timespan][key]:
                            current = statistics[timespan][key][key2]
                        else:
                            statistics[timespan][key][key2] = current = {
                                "previous": 0,
                                "current": 0,
                            }
                        current["previous"] += value2["previous"]
                        current["current"] += value2["current"]

    return json(statistics)
