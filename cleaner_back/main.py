import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from cleaner_ratelimit import RatelimitMiddleware

from .routers import challenge, downdoom, guild, oauth, radar, user, verification
from .shared import limiter
from .middleware import DBConnectErrorMiddleware


app = FastAPI()


origins = [
    "http://localhost:3000",  # TODO: remove this
    "https://cleaner.leodev.xyz",
    "https://cleaner-beta.leodev.xyz",  # TODO: remove this
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

app.include_router(challenge.router)
app.include_router(downdoom.router)
app.include_router(guild.router)
app.include_router(oauth.router)
app.include_router(radar.router)
app.include_router(user.router)
app.include_router(verification.router)

app.state.limiter = limiter


sentry_dsn = os.getenv("SECRET_SENTRY_DSN")
if sentry_dsn is not None:
    import sentry_sdk
    from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

    sentry_sdk.init(dsn=sentry_dsn)
    app = SentryAsgiMiddleware(app)  # type: ignore
