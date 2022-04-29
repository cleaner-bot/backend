import os

from async_stripe import stripe  # type: ignore
from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException, Request
import msgpack  # type: ignore

from .guild import verify_guild_access
from ..shared import with_auth, with_database, limiter


router = APIRouter()
stripe.api_key = os.getenv("SECRET_STRIPE_TOKEN")
URL_ROOT = "https://cleaner.leodev.xyz"


@router.get("/billing/stripe/checkout")
@limiter.limit("2/30", "10/1h")
async def get_stripe_checkout(
    guild_id: str,
    yearly: bool,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    await verify_guild_access(guild_id, database)

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
            "metadata": {
                "user": user_id,
                "guild": guild_id,
            },
        },
    )
    return checkout_session.url


@router.get("/billing/stripe/portal")
@limiter.limit("2/30", "10/1h")
async def get_stripe_portal(
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    customer = await database.get(f"user:{user_id}:stripe:customer")
    if customer is None:
        raise HTTPException(404, "User is not a customer")

    portal_session = stripe.billing_portal.Session.create(
        customer=customer.decode(),
        return_url=f"{URL_ROOT}/billing/stripe/portal",
    )
    return portal_session.url


WEBHOOK_IPS = {
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
async def post_stripe_webhook(
    request: Request, database: StrictRedis = Depends(with_database)
):
    ip = request.headers.get("cf-connecting-ip", None)
    if ip is None or ip not in WEBHOOK_IPS:
        raise HTTPException(400, "IP lookup failed.")

    sig_header = request.headers.get("stripe-signature", None)
    if sig_header is None:
        raise HTTPException(400, "Missing signature")

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv("SECRET_STRIPE_WEBHOOK")
        )
    except ValueError:
        raise HTTPException(400, "Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")

    print(event)
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
        operation = {"plan": msgpack.packb(1)}
        await database.hset(f"guild:{guild_id}:entitlements", operation)  # type: ignore
        payload = {"guild_id": int(guild_id), "entitlements": operation}
        await database.publish("pubsub:settings-update", msgpack.packb(payload))

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]

        guild_id = subscription["metadata"]["guild"]
        operation = {"plan": msgpack.packb(1)}
        await database.hset(f"guild:{guild_id}:entitlements", operation)  # type: ignore
        payload = {"guild_id": int(guild_id), "entitlements": operation}
        await database.publish("pubsub:settings-update", msgpack.packb(payload))

    elif event["type"] == "customer.subscription.updated":
        subscription = event["data"]["object"]

    else:
        print("Unhandled event type {}".format(event["type"]))
