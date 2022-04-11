from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path("~/.cleaner/secrets").expanduser())
load_dotenv(Path("~/.cleaner/env").expanduser())

from .main import app  # noqa: E402


__all__ = ["app"]
