import os

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/topgg/webhook", status_code=204)
async def post_topgg_webhook(request: Request):
    ip = request.headers.get("cf-connecting-ip", None)
    if ip != "159.203.105.187":
        raise HTTPException(400, "IP lookup failed.")

    auth_header = request.headers.get("authorization", None)
    expected = os.getenv("topgg/webhook-secret")
    if auth_header != expected:
        raise HTTPException(400, "Missing or invalid authorization")

    event = await request.json()

    print(event)
