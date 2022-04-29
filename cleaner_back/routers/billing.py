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
            {
                "price": price,
                "quantity": 1,
            },
        ],
        mode="subscription",
        success_url=f"{URL_ROOT}/billing/stripe/success?guild={guild_id}",
        cancel_url=f"{URL_ROOT}/billing/stripe/cancelled?guild={guild_id}",
        metadata={
            "user": user_id,
            "guild": guild_id,
        },
        customer=None if customer is None else customer.decode(),
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


@router.post("/billing/stripe/webhook", status_code=204)
async def post_stripe_webhook(
    request: Request, database: StrictRedis = Depends(with_database)
):
    sig_header = request.headers.get("STRIPE_SIGNATURE", None)
    if sig_header is None:
        raise HTTPException(400, "Missing signature")

    payload = await request.json()

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv("SECRET_STRIPE_WEBHOOK")
        )
    except ValueError:
        raise HTTPException(400, "Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(401, "Invalid signature")

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
