import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from cleaner_ratelimit import RatelimitMiddleware

from .routers import (
    assets,
    billing,
    challenge,
    downdoom,
    guild,
    oauth,
    radar,
    user,
    verification,
)
from .shared import limiter
from .middleware import DBConnectErrorMiddleware


app = FastAPI()


origins = [
    "https://cleaner.leodev.xyz",
    "http://localhost:3000",
]

app.add_middleware(RatelimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
    expose_headers=["*"],
)
app.add_middleware(DBConnectErrorMiddleware)

app.include_router(assets.router, tags=["assets"])
app.include_router(billing.router, tags=["billing"])
app.include_router(challenge.router, tags=["challenge"])
app.include_router(downdoom.router, tags=["downdoom"])
app.include_router(guild.router, tags=["guild"])
app.include_router(oauth.router, tags=["oauth"])
app.include_router(radar.router, tags=["radar"])
app.include_router(user.router, tags=["user"])
app.include_router(verification.router, tags=["verification"])

app.state.limiter = limiter


sentry_dsn = os.getenv("SECRET_SENTRY_DSN")
if sentry_dsn is not None:
    import sentry_sdk
    from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

    sentry_sdk.init(dsn=sentry_dsn)  # type: ignore
    app = SentryAsgiMiddleware(app)  # type: ignore
