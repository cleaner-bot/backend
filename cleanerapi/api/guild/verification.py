from dataclasses import dataclass

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic.response import empty
from sanic_ext import openapi, validate

from ...helpers.rpc import rpc_call
from ...helpers.settings import validate_snowflake

bp = Blueprint("GuildVerification", version=1)


@dataclass
class ChannelIdBody:
    channel_id: str


@bp.post("/guild/<guild:int>/verification-message")
@openapi.secured("user")
@openapi.body({"application/json": ChannelIdBody})
@openapi.response(204, description="Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(
    503, {"text/plain": str}, "Failed to connect to database or backend server"
)
@validate(json=ChannelIdBody)
async def post_verification_message(
    request: Request, guild: int, body: ChannelIdBody, database: Redis[bytes]
) -> HTTPResponse:
    if not validate_snowflake(body.channel_id):
        return text("Invalid channel id", 400)

    response = await rpc_call(
        database, "verification:post-message", guild, int(body.channel_id)
    )
    if not response["ok"]:
        return text(response["message"], 409)
    return empty()
