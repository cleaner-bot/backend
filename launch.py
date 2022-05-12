import os
from pathlib import Path

from dotenv import load_dotenv
from secretclient import request

load_dotenv(Path("~/.cleaner/env/backend").expanduser())


def _load_secrets():
    fields = (
        "sentry/dsn",
        "discord/bot-token",
        "discord/client-secret",
        "discord/client-id",
        "hcaptcha/secret",
        "hcaptcha/sitekey",
        "backend/jwt-secret",
        "backend/cdn-secret",
        "stripe/api-token",
        "stripe/webhook-secret",
        "coinbase/api-token",
        "coinbase/webhook-secret",
        "cloudflare/email",
        "cloudflare/api-key",
        "cloudflare/zone",
        "topgg/webhook-secret",
    )
    identity = Path("~/.cleaner/identity").expanduser().read_text()
    for key, value in request(bytes.fromhex(identity), fields, os.getenv("SECRET_HOST")).items():
        os.environ[key] = value


_load_secrets()
del _load_secrets


from cleaner_back import app  # noqa: E402

__all__ = ["app"]
