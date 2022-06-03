import os
from pathlib import Path

from dotenv import load_dotenv
from secretclient import request

load_dotenv(Path("~/.cleaner/env/backend").expanduser())


def _load_secrets() -> None:
    fields = (
        "sentry/dsn",
        "discord/client-secret",
        "discord/client-id",
        "redis/password",
        "hcaptcha/secret",
        "hcaptcha/sitekey",
        "backend/jwt-secret",
        "backend/cdn-secret",
        "stripe/api-token",
        "stripe/webhook-secret",
        "coinbase/api-token",
        "coinbase/webhook-secret",
        "cloudflare/api-token",
        "cloudflare/zone",
        "topgg/webhook-secret",
        "dlistgg/webhook-secret",
    )
    identity = Path("~/.cleaner/identity").expanduser().read_text()
    host = os.getenv("secret/host")
    if host is None:
        raise RuntimeError("secret/host env variable is unset")
    for key, value in request(bytes.fromhex(identity), fields, host).items():
        os.environ[key] = value


_load_secrets()
del _load_secrets


from cleaner_back import app  # noqa: E402

__all__ = ["app"]
