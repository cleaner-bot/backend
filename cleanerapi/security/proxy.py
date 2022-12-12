import typing

from coredis import Redis
from httpx import AsyncClient
from sanic import Request


async def is_request_from_proxy(request: Request) -> bool:
    http_client = typing.cast(AsyncClient, request.app.ctx.http_client)
    database = typing.cast(Redis[bytes], request.app.ctx.database)
    cached = await database.get(f"cache:ip:{request.ip}")
    if cached is not None:
        return cached == b"1"
    asn = typing.cast(str, request.headers["X-Connecting-Asn"])
    if await database.sismember("cache:hosting-asn", asn):
        return True
    # cannot use https without paying, wtf?
    response = await http_client.get(
        f"http://ip-api.com/json/{request.ip}?fields=status,mobile,proxy,hosting"
    )
    response.raise_for_status()
    data = response.json()
    print("ipcheck", data)
    is_proxy = data["proxy"] or data["hosting"]
    if data["hosting"]:
        await database.sadd("cache:hosting-asn", (asn,))
    await database.set(f"cache:ip:{request.ip}", "1" if is_proxy else "0", ex=60 * 60)
    return bool(is_proxy)
