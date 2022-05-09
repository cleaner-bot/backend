import asyncio
import os

from downdoom import Client
from fastapi import APIRouter

router = APIRouter()

host = os.getenv("DOWNDOOM_HOST")
client = None if host is None else Client("backend", host)
downdoom_task = None


@router.on_event("startup")
def on_startup():
    global downdoom_task
    if client is not None:
        downdoom_task = asyncio.create_task(client.run())


@router.on_event("shutdown")
def on_shutdown():
    if downdoom_task is not None:
        downdoom_task.cancel()
