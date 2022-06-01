import os

import msgpack  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from jose import jws  # type: ignore

from ..shared import limiter, print_request, with_database

router = APIRouter()


@router.post("/integrations/topgg/webhook", status_code=204)
@limiter.only_count_failed
async def post_topgg_webhook(
    request: Request, database: Redis = Depends(with_database)
):
    ip = request.headers.get("cf-connecting-ip", None)
    if ip != "159.203.105.187":
        raise HTTPException(400, "IP lookup failed.")

    auth_header = request.headers.get("authorization", None)
    expected = os.getenv("topgg/webhook-secret")
    if auth_header != expected:
        raise HTTPException(400, "Missing or invalid authorization")

    event = await request.json()

    await database.publish("pubsub:integrations:topgg-vote", msgpack.packb(event))


@router.post("/integrations/dlistgg/webhook", status_code=204)
@limiter.only_count_failed
async def post_dlist_webhook(
    request: Request,
    database: Redis = Depends(with_database),
):
    body = (await print_request(request)).decode()
    secret = os.getenv("dlistgg/webhook-secret")
    try:
        event = jws.verify(body, secret, algorithms=["HS256"])
    except jws.JWSError:
        raise HTTPException(400, "Invalid signature")

    print(event)
