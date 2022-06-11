import typing

import msgpack  # type: ignore
from coredis import Redis
from fastapi import APIRouter, Depends, HTTPException

from ..schemas.models import RadarInfo
from ..schemas.types import TRadarInfo
from ..shared import with_database

router = APIRouter()


@router.get("/radar", response_model=RadarInfo)
async def get_radar(database: Redis[bytes] = Depends(with_database)) -> TRadarInfo:
    data = await database.get("radar")
    if data is None:
        raise HTTPException(404, "No data available currently.")
    return typing.cast(TRadarInfo, msgpack.unpackb(data))
