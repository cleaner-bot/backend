
import typing

from coredis import StrictRedis
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cleaner_conf import entitlements, config, ValidationError
from ..shared import with_auth, with_database, limiter, is_developer, has_entitlement, get_guilds, get_userme
from ..models import DetailedGuildInfo, DownloadInfo


router = APIRouter(tags=["guild"])

async def check_guild(user_id: str, guild_id: str, database: StrictRedis):
    guilds = await get_guilds(database, user_id)
    for guild in guilds:
        if guild["id"] == guild_id:
            return guild
    raise HTTPException(404, "Guild not found")


@router.get("/guild/{guild_id}", response_model=DetailedGuildInfo)
async def get_guild(
    request: Request,
    response: Response,
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    try:
        guild = await check_guild(user_id, guild_id, database)
    except HTTPException:
        guild = None

    user = await get_userme(database, user_id)
    if is_developer(user_id):
        user["is_dev"] = False
    
    if not await database.exists(f"guild:{guild_id}:sync:added"):
        guild = None
    
    if guild is None:
        return {
            "user": user
        }

    guild_entitlements = {
        k: v.decode() if (v := await database.get(f"guild:{guild_id}:entitlement:{k}")) is not None else value.to_string(value.default)
        for k, value in entitlements.items() if not value.hidden
    }
    guild_config = {
        k: v.decode() if (v := await database.get(f"guild:{guild_id}:config:{k}")) is not None else value.to_string(value.default)
        for k, value in config.items() if not value.hidden
    }

    return {
        "guild": {
            "id": guild["id"],
            "name": guild["name"],
            "roles": [
                {
                    "name": "test",
                    "id": "1",
                    "can_control": True,
                    "is_managed": False
                },
                {
                    "name": "test2",
                    "id": "2",
                    "can_control": True,
                    "is_managed": False
                },
                {
                    "name": "bot",
                    "id": "3",
                    "can_control": False,
                    "is_managed": True
                },
                {
                    "name": "test3",
                    "id": "4",
                    "can_control": False,
                    "is_managed": False
                },
            ],
            "channels": [],
            "me": {
                "permissions": {
                    "administrator": True
                }
            }
        },
        "entitlements": guild_entitlements,
        "config": guild_config,
        "user": user
    }


@router.patch("/guild/{guild_id}/config", status_code=204)
async def patch_guild_config(
    request: Request,
    response: Response,
    guild_id: str,
    changes: typing.Dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    guild = await check_guild(user_id, guild_id, database)
    
    for key, value in changes.items():
        if key not in config:
            raise HTTPException(400, f"key not found: {key}")
        try:
            config[key].validate_string(value)
        except ValidationError as e:
            raise HTTPException(400, f"invalid value for {key}: {e.args[0]}")

    for key, value in changes.items():
        await database.set(f"guild:{guild_id}:config:{key}", value)

    # TODO: sync with bot


@router.patch("/guild/{guild_id}/entitlement", status_code=204)
async def patch_guild_entitlement(
    request: Request,
    response: Response,
    guild_id: str,
    changes: typing.Dict[str, str],
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    guild = await check_guild(user_id, guild_id, database)
    
    if not is_developer(user_id):
        raise HTTPException(403, "Not developer")

    for key, value in changes.items():
        if key not in entitlements:
            raise HTTPException(400, f"key not found: {key}")
        try:
            entitlements[key].validate_string(value)
        except ValidationError as e:
            raise HTTPException(400, f"invalid value for {key}: {e.args[0]}")

    for key, value in changes.items():
        await database.set(f"guild:{guild_id}:entitlement:{key}", value)

    # TODO: sync with bot


@router.post("/guild/{guild_id}/challenge/embed", status_code=204)
@limiter.limit("2/10s")
async def post_guild_challenge_embed(
    request: Request,
    response: Response,
    guild_id: str,
    channel: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    raise HTTPException(500, "TODO")


@router.get("/guild/{guild_id}/logging/downloads", response_model=typing.List[DownloadInfo])
async def get_guild_logging_downloads(
    request: Request,
    response: Response,
    guild_id: str,
    user_id: str = Depends(with_auth),
    database: StrictRedis = Depends(with_database),
):
    guild = await check_guild(user_id, guild_id, database)

    if not await has_entitlement(database, guild_id, "logging_downloads"):
        raise HTTPException(403, "Guild does not have the 'logging_downloads' entitlement")
    
    return [
        { "year": 2021, "month": 10, "expired": True },
        { "year": 2021, "month": 11, "expired": True },
        { "year": 2021, "month": 12, "expired": False },
        { "year": 2022, "month": 1, "expired": False },
        { "year": 2022, "month": 2, "expired": False },
    ]
