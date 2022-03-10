from coredis import StrictRedis  # type: ignore
from fastapi import APIRouter, Depends, Request, Response

from .guild import get_guilds
from ..shared import with_auth, with_database, limiter
from ..models import GuildInfo


router = APIRouter(tags=["user"])


# @router.get("/user/@me", response_model=UserInfo)
# @limiter.limit("5/5")
# async def user_me(
#     request: Request,
#     response: Response,
#     user_id: str = Depends(with_auth),
#     database: StrictRedis = Depends(with_database),
# ):
#     return await get_userme(database, user_id)


# @router.get("/user/@me/account", response_model=Account)
# @limiter.limit("5/5")
# async def user_me_account(
#     request: Request,
#     response: Response,
#     user_id: str = Depends(with_auth),
#     database: StrictRedis = Depends(with_database),
# ):
#     userobj = await get_userme(database, user_id)

#     return {"user": userobj, "subscriptions": [], "receipts": []}


@router.delete("/user/@me/sessions", status_code=204)
@limiter.limit("2/5minute")
async def user_me_delete_sessions(
    request: Request,
    response: Response,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    sessions = []
    async for session in database.scan_iter(f"user:{user_id}:dash:session:*"):
        sessions.append(session)
    if sessions:
        await database.delete(*sessions)


@router.get("/user/@me/guilds", response_model=list[GuildInfo])
async def user_me_guilds(
    request: Request,
    response: Response,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        guild_id = guild["id"]
        guild["is_added"] = await database.exists(f"guild:{guild_id}:sync:added")
    return guilds
