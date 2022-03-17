import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from cleaner_ratelimit import RatelimitMiddleware

from .routers import challenge, guild, oauth, radar, user
from .shared import limiter


app = FastAPI()


origins = [
    "http://localhost:3000",
    "https://cleaner.leodev.xyz",
    "https://cleaner-beta.leodev.xyz",
]

app.add_middleware(RatelimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(challenge.router)
app.include_router(guild.router)
app.include_router(oauth.router)
app.include_router(radar.router)
app.include_router(user.router)

app.state.limiter = limiter


sentry_dsn = os.getenv("SECRET_SENTRY_DSN")
if sentry_dsn is not None:
    import sentry_sdk
    from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

    sentry_sdk.init(dsn=sentry_dsn)
    app = SentryAsgiMiddleware(app)  # type: ignore
