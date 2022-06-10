import os
import typing
from datetime import datetime

import msgpack  # type: ignore
from async_commerce_coinbase import Coinbase, webhook
from async_commerce_coinbase.resources.charge import Charge
from async_stripe import stripe  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException, Request

from ..shared import limiter, with_auth, with_database
from .guild import verify_guild_access

router = APIRouter()
stripe.api_key = os.getenv("stripe/api-token")
coinbase_api_key = os.getenv("coinbase/api-token")
coinbase = Coinbase(coinbase_api_key) if coinbase_api_key else None
del coinbase_api_key
URL_ROOT = "https://cleanerbot.xyz"


@router.get("/billing/stripe/checkout")
@limiter.limit("2/30", "10/1h")
async def get_stripe_checkout(
    guild_id: str,
    yearly: bool,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> str:
    await verify_guild_access(guild_id, database)

    if await database.exists((f"guild:{guild_id}:subscription",)):
        raise HTTPException(400, "Guild is already subscribed")

    customer = await database.get(f"user:{user_id}:stripe:customer")

    price = (
        "price_1KtaA2DcWhn6gU4U5jqpngZU" if yearly else "price_1KtaA2DcWhn6gU4UnlDD3vQz"
    )
    checkout_session = await stripe.checkout.Session.create(
        line_items=[
            {"price": price, "quantity": 1},
        ],
        mode="subscription",
        success_url=f"{URL_ROOT}/billing/stripe/success?guild={guild_id}",
        cancel_url=f"{URL_ROOT}/billing/stripe/cancelled?guild={guild_id}",
        customer=None if customer is None else customer.decode(),
        metadata={
            "user": user_id,
            "guild": guild_id,
        },
        subscription_data={
            "description": f"Subscription for guild: {guild_id}",
            "metadata": {
                "user": user_id,
                "guild": guild_id,
            },
        },
    )
    return checkout_session.url  # type: ignore


@router.get("/billing/stripe/portal")
@limiter.limit("2/30", "10/1h")
async def get_stripe_portal(
    guild_id: str | None = None,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> str:
    if guild_id is not None:
        customer_user, customer_platform = await database.hmget(
            f"guild:{guild_id}:subscription", ("user", "platform")
        )
        if customer_user is None:
            raise HTTPException(404, "Guild is not subscribed")
        elif user_id != customer_user.decode():
            raise HTTPException(403, "User is not original customer")
        elif customer_platform != b"stripe":
            raise HTTPException(400, "Guild subscription does not use Stripe")

    customer = await database.get(f"user:{user_id}:stripe:customer")
    if customer is None:
        raise HTTPException(404, "User is not a customer")

    portal_session = await stripe.billing_portal.Session.create(
        customer=customer.decode(),
        return_url=f"{URL_ROOT}/dash/{guild_id}/plan" if guild_id else URL_ROOT,
    )
    return portal_session.url  # type: ignore


STRIPE_WEBHOOK_IPS = {
    "3.18.12.63",
    "3.130.192.231",
    "13.235.14.237",
    "13.235.122.149",
    "18.211.135.69",
    "35.154.171.200",
    "52.15.183.38",
    "54.88.130.119",
    "54.88.130.237",
    "54.187.174.169",
    "54.187.205.235",
    "54.187.216.72",
}


@router.post("/billing/stripe/webhook", status_code=204)
@limiter.only_count_failed
async def post_stripe_webhook(
    request: Request, database: Redis[bytes] = Depends(with_database)
) -> None:
    ip = request.headers.get("cf-connecting-ip", None)
    if ip is None or ip not in STRIPE_WEBHOOK_IPS:
        raise HTTPException(400, "IP lookup failed.")

    sig_header = request.headers.get("stripe-signature", None)
    if sig_header is None:
        raise HTTPException(400, "Missing signature")

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv("stripe/webhook-secret")
        )
    except ValueError:
        raise HTTPException(400, "Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")

    # Handle the event
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session["metadata"]["user"]
        customer = session["customer"]
        await database.set(f"user:{user_id}:stripe:customer", customer)

    elif event["type"] == "checkout.session.expired":
        session = event["data"]["object"]

    elif event["type"] == "customer.subscription.created":
        subscription = event["data"]["object"]

        guild_id = subscription["metadata"]["guild"]
        user_id = subscription["metadata"]["user"]
        await database.hset(
            f"guild:{guild_id}:entitlements", {"plan": msgpack.packb(1)}
        )
        pubpayload = {"guild_id": int(guild_id), "entitlements": {"plan": 1}}
        await database.publish("pubsub:settings-update", msgpack.packb(pubpayload))

        await database.hset(
            f"guild:{guild_id}:subscription", {"user": user_id, "platform": "stripe"}
        )

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]

        guild_id = subscription["metadata"]["guild"]
        await database.hset(
            f"guild:{guild_id}:entitlements", {"plan": msgpack.packb(0)}
        )
        pubpayload = {"guild_id": int(guild_id), "entitlements": {"plan": 0}}
        await database.publish("pubsub:settings-update", msgpack.packb(pubpayload))

        await database.delete((f"guild:{guild_id}:subscription",))

    elif event["type"] == "customer.subscription.updated":
        subscription = event["data"]["object"]


@router.get("/billing/coinbase/checkout")
@limiter.limit("2/30", "10/1h")
async def get_coinbase_checkout(
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: Redis[bytes] = Depends(with_database),
) -> str:
    await verify_guild_access(guild_id, database)

    if await database.exists((f"guild:{guild_id}:subscription",)):
        raise HTTPException(400, "Guild is already subscribed")
    elif coinbase is None:
        raise HTTPException(500, "Configuration issue. Contact support")

    charge = await coinbase.create_charge(
        name="The Cleaner Pro",
        description=f"The Cleaner Pro Yearly (40€) for guild {guild_id}",
        pricing_type="fixed_price",
        local_price={"amount": 30, "currency": "EUR"},
        redirect_url=f"{URL_ROOT}/billing/coinbase/success?guild={guild_id}",
        cancel_url=f"{URL_ROOT}/billing/coinbase/cancelled?guild={guild_id}",
        metadata={"guild": guild_id, "user": user_id},
    )

    return charge["hosted_url"]


@router.post("/billing/coinbase/webhook", status_code=204)
@limiter.only_count_failed
async def post_coinbase_webhook(
    request: Request, database: Redis[bytes] = Depends(with_database)
) -> None:
    sig_header = request.headers.get("X-CC-Webhook-Signature", None)
    if sig_header is None:
        raise HTTPException(400, "Missing signature")

    payload = await request.body()
    webhook_secret = os.getenv("coinbase/webhook-secret")
    if webhook_secret is None:
        raise HTTPException(500, "Configuration issue. Contact support")

    try:
        event = webhook.verify_signature(payload, sig_header, webhook_secret)
    except ValueError:
        raise HTTPException(400, "Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")

    if event["type"] in ("charge:confirmed", "charge:resolved"):
        data = typing.cast(Charge, event["data"])
        guild_id = data["metadata"]["guild"]
        user_id = data["metadata"]["user"]
        await database.hset(
            f"guild:{guild_id}:entitlements", {"plan": msgpack.packb(1)}
        )
        pubpayload = {"guild_id": int(guild_id), "entitlements": {"plan": 1}}
        await database.publish("pubsub:settings-update", msgpack.packb(pubpayload))

        await database.hset(
            f"guild:{guild_id}:subscription",
            {
                "user": user_id,
                "platform": "coinbase",
                "started_at": datetime.utcnow().isoformat(),
            },
        )
