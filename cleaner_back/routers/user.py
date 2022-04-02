from datetime import datetime, timedelta
import os

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException
from jose import jws  # type: ignore

from .guild import get_guilds
from ..shared import with_auth, with_database, limiter, is_suspended
from ..models import GuildInfo, RemoteAuth


router = APIRouter()


# @router.get("/user/@me", response_model=UserInfo)
# @limiter.limit("5/5")
# async def user_me(
#     user_id: str = Depends(with_auth),
#     database: StrictRedis = Depends(with_database),
# ):
#     return await get_userme(database, user_id)


# @router.get("/user/@me/account", response_model=Account)
# @limiter.limit("5/5")
# async def user_me_account(
#     user_id: str = Depends(with_auth),
#     database: StrictRedis = Depends(with_database),
# ):
#     userobj = await get_userme(database, user_id)

#     return {"user": userobj, "subscriptions": [], "receipts": []}


@router.delete("/user/@me/sessions", status_code=204)
@limiter.limit("2/5minute")
async def user_me_delete_sessions(
    user_id: str = Depends(with_auth), database: StrictRedis = Depends(with_database)
):
    sessions = []
    async for session in database.scan_iter(f"user:{user_id}:dash:session:*"):
        sessions.append(session)
    if sessions:
        await database.delete(sessions)


@router.get("/user/@me/guilds", response_model=list[GuildInfo])
async def user_me_guilds(
    user_id: str = Depends(with_auth), database: StrictRedis = Depends(with_database)
):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        guild_id = guild["id"]
        guild["is_added"] = await database.hexists(f"guild:{guild_id}:sync", "added")
        guild["is_suspended"] = await is_suspended(database, guild_id)
    return guilds


@router.post("/user/@me/remote-auth")
@limiter.limit("5/1h")
async def user_me_remote_auth(
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    code = os.urandom(32).hex()
    await database.set(f"remote-auth:{code}", user_id, ex=300)
    return code


@router.post("/remote-auth")
@limiter.limit("5/1h")
async def remote_auth(auth: RemoteAuth, database: StrictRedis = Depends(with_database)):
    code = auth.code
    if len(code) != 64 or not all(x in "0123456789abcdef" for x in code):
        raise HTTPException(400, "Bad code")

    user_id = await database.get(f"remote-auth:{code}")
    if user_id is None:
        raise HTTPException(404, "Code not found or expired")
    await database.delete((f"remote-auth:{code}",))

    expires_after = 60 * 60 * 24 * 7
    expires = datetime.utcnow() + timedelta(seconds=expires_after)
    session = os.urandom(32)

    data = f"{int(expires.timestamp())}.{session.hex()}.{user_id.decode()}"
    await database.set(
        f"user:{user_id.decode()}:dash:session:{session.hex()}", 1, ex=expires_after
    )

    secret = os.getenv("SECRET_WEB_AUTH")
    token = jws.sign(data.encode(), secret, algorithm="HS256")

    return {"token": token}
