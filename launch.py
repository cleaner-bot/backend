import os
from pathlib import Path

from dotenv import load_dotenv
from secretclient import request

load_dotenv()


from cleanerapi.main import app  # noqa: E402

__all__ = ["app"]
