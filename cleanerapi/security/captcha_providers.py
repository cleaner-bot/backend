import hashlib
import json
import typing
from base64 import b64encode
from binascii import crc32

from httpx import AsyncClient
from sanic import Request, Sanic

from ..helpers.based import b64parse


class CaptchaProvider:
    @classmethod
    async def verify(cls, request: Request, *, token: str, signature: bytes) -> bool:
        raise NotImplementedError

    @classmethod
    def challenge_parameters(
        cls, app: Sanic, data: dict[str, str | int], *, signature: bytes, unique: str
    ) -> None:
        pass


class HCaptchaProvider(CaptchaProvider):
    @classmethod
    async def verify(cls, request: Request, *, token: str, signature: bytes) -> bool:
        http_client = typing.cast(AsyncClient, request.app.ctx.http_client)
        res = await http_client.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": request.app.config.HCAPTCHA_SECRET,
                "sitekey": request.app.config.HCAPTCHA_SITEKEY,
                "remoteip": request.ip,
                "response": token,
            },
        )
        data = typing.cast(HCaptchaResponse, res.json())
        print("hcaptcha -", data)
        return data["success"]

    @classmethod
    def challenge_parameters(
        cls, app: Sanic, data: dict[str, str | int], *, signature: bytes, unique: str
    ) -> None:
        data["sk"] = app.config.HCAPTCHA_SITEKEY


class TurnstileProvider(CaptchaProvider):
    @classmethod
    async def verify(cls, request: Request, *, token: str, signature: bytes) -> bool:
        http_client = typing.cast(AsyncClient, request.app.ctx.http_client)
        res = await http_client.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": request.app.config.TURNSTILE_SECRET,
                "sitekey": request.app.config.TURNSTILE_SITEKEY,
                "remoteip": request.ip,
                "response": token,
            },
        )
        data = typing.cast(TurnstileResponse, res.json())
        print("turnstile -", data)
        if data.get("cdata", "") != signature.hex():
            return False
        return data["success"]

    @classmethod
    def challenge_parameters(
        cls, app: Sanic, data: dict[str, str | int], *, signature: bytes, unique: str
    ) -> None:
        data["sk"] = app.config.TURNSTILE_SITEKEY
        data["c"] = signature.hex()
        data["a"] = unique.split("|")[0]


class ButtonProvider(CaptchaProvider):
    @classmethod
    def _signature_to_nonce(cls, signature: bytes) -> int:
        return int.from_bytes(signature[:6], "big", signed=True)

    @classmethod
    async def verify(cls, request: Request, *, token: str, signature: bytes) -> bool:
        decoded = b64parse(token)
        if decoded is None:
            print("button - not valid b64", token)
            return False

        secret_bytes = bytes([x ^ 0x86 ^ i for i, x in enumerate(decoded[:8])])
        nonce = cls._signature_to_nonce(signature)
        secret = crc32(secret_bytes)
        secret ^= nonce & 0xFFFFFFFF
        untrusted = (decoded[8] ^ ((secret >> 16) & 0xFF)) & 0xF
        if untrusted:
            print("button - click not trusted", bin(untrusted))
            return False
        values = []
        for i in range(9, len(decoded), 2):
            v1 = decoded[i] ^ (secret >> 24)
            v2 = decoded[i + 1] ^ (secret & 0xFF)
            value = int.from_bytes([v1, v2], "big", signed=True)
            values.append(value)
            secret ^= (
                value ^ (value << 8) ^ (value << 16) ^ (value << 24)
            ) & 0xFFFFFFFF

        print("button - values", values)
        if len(values) != 10:
            print("button - wrong value length", len(values), values)
            return False

        offset_x, offset_y, page_x, page_y, x, y, scroll_x, scroll_y, top, left = values
        page_x -= scroll_x + left
        page_y -= scroll_y + top
        x -= left
        y -= top
        if top <= 0:
            print("button - invalid top", top)
        elif top <= 0:
            print("button - invalid left", left)

        coordinates = ((offset_x, offset_y), (page_x, page_y), (x, y))
        print("button - coordinates", coordinates)
        for vx, vy in coordinates:
            if not 303 >= vx >= 0:
                print("button - invalid vx", vx)
                return False
            elif not 78 >= vy >= 0:
                print("button - invalid vy", vy)
                return False

        all_x, all_y = zip(*coordinates)
        delta_x = abs(offset_x - sum(map(int, all_x)) / 3)
        delta_y = abs(offset_y - sum(map(int, all_y)) / 3)

        if delta_x > 4:
            print("button - too much x delta", delta_x, all_x)
            return False
        elif delta_y > 4:
            print("button - too much y delta", delta_y, all_y)
            return False

        return True

    @classmethod
    def challenge_parameters(
        cls, app: Sanic, data: dict[str, str | int], *, signature: bytes, unique: str
    ) -> None:
        data["n"] = cls._signature_to_nonce(signature)


class ProofOfWorkProvider(CaptchaProvider):
    DIFFICULTY = 17

    @classmethod
    async def verify(cls, request: Request, *, token: str, signature: bytes) -> bool:
        try:
            data = json.loads(token)
        except json.decoder.JSONDecodeError:
            print("pow - invalid json", token)
            return False

        result = data.get("result", None)
        if (
            result is None
            or not isinstance(result, int)
            or not 0xFFFFFFFF >= result >= 0
        ):
            print("pow - invalid pow result", result)
            return False

        digest = hashlib.sha256(signature + result.to_bytes(4, "big")).digest()
        value = int.from_bytes(digest[-cls.DIFFICULTY // 8 :], "big")

        if value & ((1 << cls.DIFFICULTY) - 1):
            print("pow - not solved", bin(value))
            return False
        return True

    @classmethod
    def challenge_parameters(
        cls, app: Sanic, data: dict[str, str | int], *, signature: bytes, unique: str
    ) -> None:
        data["a"] = "SHA-256"
        data["d"] = cls.DIFFICULTY
        data["s"] = b64encode(signature).decode()


HCaptchaResponse = typing.TypedDict(
    "HCaptchaResponse",
    {
        "success": bool,
        "challenge_ts": str,
        "hostname": str,
        "credit": bool,
        "error-codes": list[str],
    },
)
TurnstileResponse = typing.TypedDict(
    "TurnstileResponse",
    {
        "success": bool,
        "challenge_ts": str,
        "hostname": str,
        "error-codes": list[str],
        "action": str,
        "cdata": str,
    },
)


providers: dict[str, typing.Type[CaptchaProvider]] = {
    "hcaptcha": HCaptchaProvider,
    "turnstile": TurnstileProvider,
    "button": ButtonProvider,
    "pow": ProofOfWorkProvider,
}
