import base64
import time
import typing

from coredis import Redis
from sanic import Blueprint, HTTPResponse, Request, text
from sanic.response import empty
from sanic_ext import openapi
from webauthn.authentication.generate_authentication_options import (
    generate_authentication_options,
)
from webauthn.authentication.verify_authentication_response import (
    verify_authentication_response,
)
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.options_to_json import options_to_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
)
from webauthn.registration.generate_registration_options import (
    generate_registration_options,
)
from webauthn.registration.verify_registration_response import (
    verify_registration_response,
)

from ...helpers.auth import UserToken, create_user_token, get_user
from ...helpers.totp import hotp
from ...security.fingerprint import fingerprint

bp = Blueprint("UserMFA", version=1)


@bp.get("/user/me/mfa")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_mfa(request: Request, database: Redis[bytes]) -> HTTPResponse:
    mfa_type = await database.hget(f"user:{request.ctx.user_token.user_id}:mfa", "type")
    if mfa_type is None:
        return text("No MFA set", 404)
    return text(mfa_type.decode())


@bp.delete("/user/me/mfa")
@openapi.summary("disables mfa and revokes all sessions")
@openapi.secured("user")
@openapi.response(204, description="Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def delete_mfa(request: Request, database: Redis[bytes]) -> HTTPResponse:
    mfa_type = await database.hget(f"user:{request.ctx.user_token.user_id}:mfa", "type")
    if mfa_type is None:
        return text("No MFA set", 404)
    if not request.ctx.user_token.is_mfa_valid():
        return text("MFA verified session required to disable MFA", 403)
    await database.delete((f"user:{request.ctx.user_token.user_id}:mfa",))
    await database.hset(
        f"user:{request.ctx.user_token.user_id}:oauth2", {"revoked": int(time.time())}
    )
    return empty()


@bp.post("/user/me/mfa/totp")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_mfa(request: Request, database: Redis[bytes]) -> HTTPResponse:
    body = request.json

    if (
        "code" not in body
        or not isinstance(body["code"], int)
        or not 999999 >= body["code"] >= 0
    ):
        return text("Missing or invalid code", 400)

    ratelimit = await database.incr(
        f"user:{request.ctx.user_token.user_id}:mfa-ratelimit"
    )
    if ratelimit == 1:
        await database.expire(
            f"user:{request.ctx.user_token.user_id}:mfa-ratelimit", 60
        )
    elif ratelimit > 5:
        return text("Ratelimited", 429)

    if "secret" in body:
        secret = body["secret"]
        try:
            raw_secret = base64.b32decode(secret + "=" * (8 - len(secret) % 8))
        except ValueError:
            return text("Invalid secret", 400)

        mfa_type = await database.hget(
            f"user:{request.ctx.user_token.user_id}:mfa", "type"
        )
        if mfa_type is not None:
            return text("MFA already set", 404)

    else:
        mfa_type, raw_secret2 = await database.hmget(
            f"user:{request.ctx.user_token.user_id}:mfa", ("type", "totp_secret")
        )
        if mfa_type is None:
            return text("MFA not setup", 409)
        elif mfa_type != b"totp" or raw_secret2 is None:
            return text("TOTP not allowed", 403)
        raw_secret = raw_secret2

    code = body["code"]

    now = int(time.time() // 30)
    for offset in range(-2, 3):
        if int(hotp(raw_secret, now + offset)) == code:
            break
    else:
        return text("Invalid TOTP", 403)

    if "secret" in body:
        await database.hset(
            f"user:{request.ctx.user_token.user_id}:mfa",
            {"type": "totp", "totp_secret": raw_secret},
        )

    user_token = typing.cast(UserToken, request.ctx.user_token)
    new_token = user_token._replace(
        mfa_timestamp=int(now // 2 - user_token.timestamp // 60 + 60),
        browser_fingerprint=fingerprint(request, "user"),
    )

    return text(create_user_token(request, new_token))


@bp.get("/user/me/mfa/u2f/r")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_registration_u2f_mfa(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    mfa_type = await database.hget(f"user:{request.ctx.user_token.user_id}:mfa", "type")
    if mfa_type is not None:
        return text("MFA is set", 404)

    user = await get_user(request, database)

    display_name = user["name"] + "#" + user["discriminator"]
    registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="The Cleaner Bot - Dashboard",
        user_id=str(request.ctx.user_token.user_id),
        user_name=display_name,
        attestation=AttestationConveyancePreference.DIRECT,
    )

    await database.hset(
        f"user:{request.ctx.user_token.user_id}:mfa",
        {"u2f_challenge": registration_options.challenge},
    )

    return text(options_to_json(registration_options), content_type="application/json")


@bp.post("/user/me/mfa/u2f/r")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_registration_u2f_mfa(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    mfa_type, challenge = await database.hmget(
        f"user:{request.ctx.user_token.user_id}:mfa", ("type", "u2f_challenge")
    )
    if mfa_type is not None:
        return text("MFA is set", 404)
    elif challenge is None or challenge == b"":
        return text("No attestation expected", 404)

    body = request.json
    credential = RegistrationCredential(
        raw_id=base64.b64decode(body["id"]),
        id=bytes_to_base64url(base64.b64decode(body["id"])),
        response=AuthenticatorAttestationResponse(
            attestation_object=base64.b64decode(body["response"]["attestation"]),
            client_data_json=base64.b64decode(body["response"]["data"]),
        ),
    )

    # Registration Response Verification
    try:
        registration_verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin="http://localhost:3000",
            expected_rp_id="localhost",
        )
    except InvalidRegistrationResponse:
        return text("Verification failed", 400)

    await database.hset(
        f"user:{request.ctx.user_token.user_id}:mfa",
        {
            "type": "u2f",
            "u2f_cretential_pubkey": registration_verification.credential_public_key,
            "u2f_cretential_id": registration_verification.credential_id,
            "u2f_sign_count": registration_verification.sign_count,
            "u2f_challenge": b"",
        },
    )

    user_token = typing.cast(UserToken, request.ctx.user_token)
    new_token = user_token._replace(
        mfa_timestamp=int(time.time() // 60 - user_token.timestamp // 60 + 60),
        browser_fingerprint=fingerprint(request, "user"),
    )

    return text(create_user_token(request, new_token))


@bp.get("/user/me/mfa/u2f/a")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def get_authentication_u2f_mfa(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    mfa_type, u2f_cretential_id = await database.hmget(
        f"user:{request.ctx.user_token.user_id}:mfa", ("type", "u2f_cretential_id")
    )
    if mfa_type is None:
        return text("MFA not setup", 409)
    elif mfa_type != b"u2f":
        return text("U2F not allowed", 403)

    authentication_options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[PublicKeyCredentialDescriptor(id=u2f_cretential_id)],
    )

    await database.hset(
        f"user:{request.ctx.user_token.user_id}:mfa",
        {"u2f_challenge": authentication_options.challenge},
    )

    return text(
        options_to_json(authentication_options), content_type="application/json"
    )


@bp.post("/user/me/mfa/u2f/a")
@openapi.secured("user")
@openapi.response(200, {"text/plain": str}, "Success")
@openapi.response(401, {"text/plain": "Unauthorized"}, "Unauthorized")
@openapi.response(500, {"text/plain": str}, "Internal error")
@openapi.response(503, {"text/plain": str}, "Failed to connect to database")
async def post_authentication_u2f_mfa(
    request: Request, database: Redis[bytes]
) -> HTTPResponse:
    mfa_type, credential_public_key, sign_count, challenge = await database.hmget(
        f"user:{request.ctx.user_token.user_id}:mfa",
        ("type", "u2f_cretential_pubkey", "u2f_sign_count", "u2f_challenge"),
    )
    if mfa_type is None:
        return text("MFA not setup", 409)
    elif mfa_type != b"u2f":
        return text("U2F not allowed", 403)
    elif challenge is None or challenge == b"" or sign_count is None:
        return text("No attestation expected", 404)

    assert credential_public_key

    body = request.json
    credential = AuthenticationCredential(
        raw_id=base64.b64decode(body["id"]),
        id=bytes_to_base64url(base64.b64decode(body["id"])),
        response=AuthenticatorAssertionResponse(
            authenticator_data=base64.b64decode(body["response"]["authenticator"]),
            client_data_json=base64.b64decode(body["response"]["data"]),
            signature=base64.b64decode(body["response"]["signature"]),
        ),
    )

    # Registration Response Verification
    try:
        authentication_verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin="http://localhost:3000",
            expected_rp_id="localhost",
            credential_public_key=credential_public_key,
            credential_current_sign_count=int(sign_count),
        )
    except InvalidAuthenticationResponse:
        return text("Verification failed", 400)

    await database.hset(
        f"user:{request.ctx.user_token.user_id}:mfa",
        {
            "u2f_challenge": b"",
            "u2f_sign_count": authentication_verification.new_sign_count,
        },
    )

    user_token = typing.cast(UserToken, request.ctx.user_token)
    new_token = user_token._replace(
        mfa_timestamp=int(time.time() // 60 - user_token.timestamp // 60 + 60),
        browser_fingerprint=fingerprint(request, "user"),
    )

    return text(create_user_token(request, new_token))
