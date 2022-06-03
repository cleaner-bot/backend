import asyncio
import os

from downdoom import Client
from fastapi import APIRouter

router = APIRouter()

host = os.getenv("downdoom/host")
client = None if host is None else Client("backend", host)
downdoom_task = None


@router.on_event("startup")
def on_startup() -> None:
    global downdoom_task
    if client is not None:
        downdoom_task = asyncio.create_task(client.run())


@router.on_event("shutdown")
def on_shutdown() -> None:
    if downdoom_task is not None:
        downdoom_task.cancel()
