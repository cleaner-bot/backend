import re
import typing

import filterrules
import msgpack  # type: ignore
from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, json, text
from sanic.response import empty
from sanic_ext import openapi

from ...helpers.settings import get_entitlement_field

bp = Blueprint("FIlterRules", version=1)
ALL_PHASES = {
    "member_create": {
        "actions": ("disabled", "allow", "kickonly", "banonly", "auto"),
        "scopes": ("user", "member"),
    },
    "member_update": {
        "actions": ("disabled", "allow", "kickonly", "banonly", "auto"),
        "scopes": ("user", "member"),
    },
    "message_create": {
        "actions": (
            "disabled",
            "allow",
            "delete",
            "challenge",
            "kickonly",
            "banonly",
            "auto",
        ),
        "scopes": ("user", "member", "message"),
    },
    "message_update": {
        "actions": (
            "disabled",
            "allow",
            "delete",
            "challenge",
            "kickonly",
            "banonly",
            "auto",
        ),
        "scopes": ("user", "member", "message"),
    },
}
SCOPES = {
    "user": {
        "user.id": int,
        "user.username": bytes,
        "user.discriminator": bytes,
        "user.created_at": int,
        "user.has_avatar": bool,
        "user.avatar_hash": bytes,
        "user.flags": int,
    },
    "member": {
        "member.nickname": bytes,
        "member.joined_at": int,
    },
    "message": {
        "message.content": bytes,
        "message.has_embeds": bool,
        "message.has_attachments": bool,
        "message.type": int,
        "message.flags": int,
    },
}
FUNCTIONS: dict[str, tuple[tuple[type, ...], type]] = {
    "regex_match": ((bytes, bytes), bool),
    "len": ((bytes,), bool),
    "lower": ((bytes,), bytes),
    "upper": ((bytes,), bytes),
    "starts_with": ((bytes,), bool),
    "contains": ((bytes,), bool),
    "ends_with": ((bytes,), bool),
    "to_string": ((object,), bytes),
}
RULES_PER_PHASE = 5


@bp.get("/guild/<guild:int>/filterrules")
@openapi.summary("returns a list of all filterrules and phases")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_filterrules(
    request: Request, guild: int, database: Redis[bytes]
) -> HTTPResponse:
    if await get_entitlement_field(
        database, guild, "plan"
    ) < await get_entitlement_field(database, guild, "filterrules"):
        return text("Missing filterrules entitlement", 403)

    rules = {}
    for phase in ALL_PHASES:
        raw_rules = await database.lrange(f"guild:{guild}:filterrules:{phase}", 0, -1)
        rules[phase] = [
            {"action": action, "name": name, "code": code.decode()}
            for action, name, code in map(msgpack.unpackb, raw_rules)
        ]
    return json(rules)


@bp.post("/guild/<guild:int>/filterrules/<phase:str>")
@openapi.summary("create a new filterrule")
@openapi.secured("user")
@openapi.response(200, {"application/json"}, "Success")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_filterrules_phase(
    request: Request, guild: int, phase: str, database: Redis[bytes]
) -> HTTPResponse:
    if await get_entitlement_field(
        database, guild, "plan"
    ) < await get_entitlement_field(database, guild, "filterrules"):
        return text("Missing filterrules entitlement", 403)

    if phase not in ALL_PHASES:
        return text("Unknown phase", 404)
    length = await database.llen(f"guild:{guild}:filterrules:{phase}")
    if length >= RULES_PER_PHASE:
        return text(f"Limit of rules ({RULES_PER_PHASE}) reached.", 403)

    data = typing.cast(bytes, msgpack.packb(("disabled", f"rule {length + 1}", b"")))
    new_length = await database.rpush(f"guild:{guild}:filterrules:{phase}", (data,))
    if new_length >= RULES_PER_PHASE:
        await database.rpop(f"guild:{guild}:filterrules:{phase}")
        return text(
            f"Limit of rules ({RULES_PER_PHASE}) reached. (race condition triggered)",
            403,
        )

    return json({"action": "disabled", "name": f"rule {length + 1}", "code": ""})


@bp.patch("/guild/<guild:int>/filterrules/<phase:str>/<index:int>")
@openapi.summary("create a new filterrule")
@openapi.secured("user")
@openapi.response(204, description="Updated")
@openapi.response(400, {"text/plain": str}, "Bad request")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(403, {"text/plain": str}, "Forbidden")
@openapi.response(404, {"text/plain": str}, "Guild not found")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def patch_filterrules_phase_rule(
    request: Request, guild: int, phase: str, index: int, database: Redis[bytes]
) -> HTTPResponse:
    if await get_entitlement_field(
        database, guild, "plan"
    ) < await get_entitlement_field(database, guild, "filterrules"):
        return text("Missing filterrules entitlement", 403)

    if phase not in ALL_PHASES:
        return text("Unknown phase", 404)
    elif not RULES_PER_PHASE > index >= 0:
        return text("Invalid rule index", 400)
    current = await database.lindex(f"guild:{guild}:filterrules:{phase}", index)
    if current is None:
        return text("Unknown rule", 404)
    current_action, current_name, current_code = msgpack.unpackb(current)

    body = request.json
    if "action" not in body or body["action"] not in ALL_PHASES[phase]["actions"]:
        body["action"] = current_action
    if "name" not in body or not re.fullmatch("^[a-zA-Z ]{2,32}$", body["name"]):
        body["name"] = current_name
    if "code" not in body:
        body["code"] = current_code.decode()

    if len(body["code"]) >= 4096:
        return text("Code must not be longer than 4096 bytes.", 422)
    elif body["code"] != current_code.decode():
        try:
            ast = filterrules.parse(body["code"].encode())
        except Exception as e:
            return text(e.args[0], 422)

        variables = {}
        for scope in ALL_PHASES[phase]["scopes"]:
            variables.update(SCOPES[scope])
        err = filterrules.lint(ast, variables, FUNCTIONS)
        if err is not None:
            return text(err, 422)

    data = typing.cast(
        bytes, msgpack.packb((body["action"], body["name"], body["code"].encode()))
    )
    await database.lset(f"guild:{guild}:filterrules:{phase}", index, data)
    return empty()
