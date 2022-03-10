from coredis import StrictRedis
from coredis.exceptions import ConnectionError
from httpx import AsyncClient, RequestError
from fastapi import APIRouter, Depends, Request, Response

from ..shared import with_database, with_asyncclient, limiter


router = APIRouter()


@router.get("/status")
async def get_status():
    # TODO
    return {}
