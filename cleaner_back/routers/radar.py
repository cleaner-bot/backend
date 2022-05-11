import msgpack  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException

from ..models import RadarInfo
from ..shared import with_database

router = APIRouter()


@router.get("/radar", response_model=RadarInfo)
async def get_radar(database: Redis = Depends(with_database)):
    data = await database.get("radar")
    if data is None:
        raise HTTPException(500, "No data available currently.")
    return msgpack.unpackb(data)
