import asyncio
import os
import time
import typing

import msgpack  # type: ignore
from coredis import Redis
from coredis.response.types import PubSubMessage
from sanic.exceptions import SanicException

RPCResponse = typing.TypedDict(
    "RPCResponse", {"ok": bool, "message": str, "data": typing.Any}
)
_calls: dict[str, asyncio.Queue[PubSubMessage]] = {}


async def rpc_call(
    database: Redis[bytes], fn_name: str, *args: typing.Any
) -> RPCResponse:
    call_id = os.urandom(16).hex()
    queue: asyncio.Queue[PubSubMessage]
    try:
        _calls[call_id] = queue = asyncio.Queue()

        packet = msgpack.packb((call_id, fn_name, args))
        await database.publish("pubsub:rpc", packet)

        timeout = time.monotonic() + 5
        while (left := timeout - time.monotonic()) > 0.1:
            message = await asyncio.wait_for(queue.get(), left)
            if message["data"] == b"ACK":
                timeout += 25
            else:
                return typing.cast(
                    RPCResponse, msgpack.unpackb(message["data"], use_list=False)
                )

    except asyncio.TimeoutError:
        raise SanicException("Failed to connect to backend server", 503)

    finally:
        del _calls[call_id]

    raise SanicException("Failed to connect to backend server", 503)


async def rpc_agent(database: Redis[bytes]) -> None:
    pubsub = database.pubsub(ignore_subscribe_messages=True)
    await pubsub.psubscribe("pubsub:rpc:*")
    while True:
        message = await pubsub.get_message()
        if message is None or message["type"] != "pmessage":
            continue
        call_id = message["channel"].decode().split(":")[-1]
        call = _calls.get(call_id, None)
        if call is not None:
            await call.put(message)
