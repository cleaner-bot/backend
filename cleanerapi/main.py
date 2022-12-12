from coredis import Redis
from hikari import RESTApp
from httpx import AsyncClient
from sanic import Sanic

from .api import api
from .error_handler import CustomErrorHandler
from .helpers.rpc import rpc_agent

app = Sanic("cleanerapi")

# cors settings need to be set before anything else
app.config.CORS_ORIGINS = [
    "http://localhost.test",
    "http://localhost:3000",
    "https://cleanerbot.xyz",
    "https://staging.cleanerbot.xyz",
]
app.config.CORS_ALLOW_HEADERS = ["content-type", "authorization"]
app.config.CORS_SUPPORTS_CREDENTIALS = True
app.config.CORS_ALWAYS_SEND = True

_redis_singleton = app.ctx.database = Redis.from_url(app.config.REDIS_URL)
_hikari_singleton = app.ctx.hikari_rest = RESTApp()
_httpx_singleton = app.ctx.http_client = AsyncClient(
    headers={"user-agent": "CleanerBot (cleanerbot.xyz 0.2.0)"}
)
app.ext.add_dependency(Redis[bytes], lambda *_: _redis_singleton)
app.ext.dependency(_httpx_singleton)
app.ext.dependency(_hikari_singleton)

app.ext.openapi.add_security_scheme(
    "user", "http", description="user authentication token"
)

app.config.ACCESS_LOG = True

# cloudflare specific settings
app.config.REAL_IP_HEADER = "cf-connecting-ip"
app.config.REQUEST_ID_HEADER = "cf-ray"

app.add_task(rpc_agent(_redis_singleton))
app.blueprint(api)
app.error_handler = CustomErrorHandler()
