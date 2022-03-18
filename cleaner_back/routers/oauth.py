from datetime import datetime, timedelta
import os
from urllib.parse import urlencode

from coredis import StrictRedis  # type: ignore
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from hikari import BadRequestError, UnauthorizedError, Permissions
from hikari.urls import BASE_URL
from hikari.impl import RESTClientImpl
from jose import jws  # type: ignore

from ..shared import with_database, with_hikari, hikari_rest, home, limiter


router = APIRouter()


base = "/oauth2/authorize"
redirect_uri = "https://cleaner-beta.leodev.xyz/oauth-comeback"  # TODO: fix domain
response_type = "code"
scopes = ["identify", "guilds", "email"]

allowed_components = (
    "",
    "firewall",
    "antispam",
    "slowmode",
    "challenge",
    "logging",
    "impersonation",
    "workers",
    "backup",
    "bot",
    "plan",
    "contact",
    "dev",
)


@router.get("/oauth/redirect", response_class=RedirectResponse)
async def oauth_redirect(
    bot: bool = False,
    with_admin: bool = False,
    guild: str = None,
    component: str = None,
    flow: str = None,
    database: StrictRedis = Depends(with_database),
):
    if flow is not None:
        if len(flow) != 64 or not all(x in "0123456789abcdef" for x in flow):
            raise HTTPException(400, "Invalid flow")
        redirect_target = f"{home}/challenge?flow={flow}"
    elif guild is None:
        redirect_target = f"{home}/dash"
    elif component is None:
        if not guild.isdigit():
            raise HTTPException(400, "Invalid guild id")
        redirect_target = f"{home}/dash/{guild}"
    else:
        if not guild.isdigit():
            raise HTTPException(400, "Invalid guild id")
        if component not in allowed_components:
            raise HTTPException(400, "Invalid component")
        redirect_target = f"{home}/dash/{guild}/{component}"

    state = os.urandom(64).hex()
    await database.set(f"dash:oauth:state:{state}", redirect_target, ex=600)

    client_id = os.getenv("SECRET_CLIENT_ID")
    if client_id is None:
        raise HTTPException(500, "Configuration issue, please contact support")

    query = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": " ".join(scopes),
        "state": state,
        "prompt": "none",
    }

    if bot:
        permissions = (
            Permissions.BAN_MEMBERS
            | Permissions.KICK_MEMBERS
            | Permissions.SEND_MESSAGES
            | Permissions.VIEW_CHANNEL
            | Permissions.EMBED_LINKS
            | Permissions.MANAGE_MESSAGES
            | Permissions.MANAGE_GUILD
            | Permissions.MANAGE_CHANNELS
            | Permissions.MANAGE_ROLES
            | Permissions.MANAGE_NICKNAMES
            | Permissions.MODERATE_MEMBERS
        )
        if with_admin:
            permissions |= Permissions.ADMINISTRATOR

        query["scope"] += " bot applications.commands"
        query["permissions"] = str(int(permissions))
        if guild:
            query["guild_id"] = guild
            query["disable_guild_select"] = "true"

    return f"{BASE_URL}{base}?{urlencode(query)}"


@router.post("/oauth/callback")
@limiter.limit("2/1s", "4/10s")
async def oauth_callback(
    code: str = None,
    state: str = None,
    database: StrictRedis = Depends(with_database),
    hikari: RESTClientImpl = Depends(with_hikari),
):
    if state is None:
        raise HTTPException(400, "Missing state param")

    if len(state) != 128 or not all(x in "0123456789abcdef" for x in state):
        raise HTTPException(400, "Invalid state")

    redirect_target = await database.get(f"dash:oauth:state:{state}")
    if redirect_target is None:
        raise HTTPException(404, "State not found")

    if code is None:
        return {"redirect": redirect_target}

    client_secret = os.getenv("SECRET_CLIENT")
    client_id = os.getenv("SECRET_CLIENT_ID")
    if client_secret is None or client_id is None:
        raise HTTPException(500, "Configuration issue, please contact support")

    try:
        authtoken = await hikari.authorize_access_token(
            int(client_id), client_secret, code, redirect_uri
        )
    except BadRequestError:
        await database.delete(f"dash:oauth:state:{state}")
        raise HTTPException(400, "Invalid code")

    try:
        async with hikari_rest.acquire(authtoken.access_token, "Bearer") as selfbot:
            auth = await selfbot.fetch_authorization()

    except UnauthorizedError:
        raise HTTPException(401, "Very fast deauthorization you got there")

    if set(scopes) != set(auth.scopes) or auth.user is None:
        await database.delete(f"dash:oauth:state:{state}")
        raise HTTPException(400, "Scope mismatch")

    expires_after = 60 * 60 * 24 * 7
    expires = datetime.utcnow() + timedelta(seconds=expires_after)
    session = os.urandom(32)

    data = f"{int(expires.timestamp())}.{session.hex()}.{auth.user.id}"

    await database.set(
        f"user:{auth.user.id}:oauth:token", authtoken.access_token, ex=expires_after
    )
    await database.set(
        f"user:{auth.user.id}:dash:session:{session.hex()}", 1, ex=expires_after
    )

    # userobj = {
    #     "id": auth.user.id,
    #     "name": auth.user.username,
    #     "avatar": auth.user.make_avatar_url(ext="jpg", size=64).url,
    # }
    # await database.set(f"cache:user:@me:{auth.user.id}", json.dumps(userobj), ex=30)

    secret = os.getenv("SECRET_WEB_AUTH")
    token = jws.sign(data.encode(), secret, algorithm="HS256")

    return {"token": token, "redirect": redirect_target.decode()}
