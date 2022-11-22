from __future__ import annotations

import enum
import typing
from binascii import crc32
from datetime import datetime

from sanic import Request

from .based import b64parse


SEC_FETCH_HEADERS = {"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"}
SEC_CH_UA_HEADERS = {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
WINDOWS_FONTS = {
    "Cambria Math",
    "Nirmala UI",
    "Leelawadee UI",
    "HoloLens MDL2 Assets",
    "Segoe Fluent Icons",
}
APPLE_FONTS = {
    "Helvetica Neue",
    "Luminari",
    "PingFang HK Light",
    "Futura Bold",
    "Valvji",
    "Chakra Petch",
}
LINUX_FONTS = {
    "Arimo",
    "MONO",
    "Ubuntu",
    "Noto Color Emoji",
    "Dancing Script",
    "Droid Sans Mono",
    "Roboto",
}


class BrowserCheckResult(enum.Enum):
    OK = enum.auto()
    SUSPICIOUS = enum.auto()
    TAMPERED = enum.auto()


def browser_check(request: Request, browserdata: BrowserData) -> BrowserCheckResult:
    # check if payload makes sense
    browserdata_shape = {
        k: typing.ForwardRef(type(v).__name__) for k, v in browserdata.items()
    }
    # using a string compare cuz everything else just does not work
    if str(browserdata_shape) != str(BrowserData.__annotations__):
        print("shape of browserdata does not match", browserdata_shape, browserdata)
        return BrowserCheckResult.TAMPERED

    # check if the values make sense
    if browserdata["t1"] >= browserdata["t2"]:
        print("current before page load", browserdata)
        return BrowserCheckResult.TAMPERED

    time_delta = abs(browserdata["t2"] - datetime.now().timestamp() * 1000)
    if time_delta > 60_000:
        print("time delta too large", time_delta, browserdata)
        return BrowserCheckResult.SUSPICIOUS

    # check if sequence number makes sense
    lower_bounds = (browserdata["t1"] + browserdata["t2"]) & 0xFFFF
    upper_bounds = (browserdata["t1"] + browserdata["t2"] + 1000) & 0xFFFF
    if lower_bounds > upper_bounds:  # its at the wrap around point
        if upper_bounds < browserdata["s"] < lower_bounds:
            print("sequence out of bounce (wrapped)", browserdata)
            return BrowserCheckResult.TAMPERED
    else:
        if not upper_bounds >= browserdata["s"] >= lower_bounds:
            print("sequence out of bounce (not wrapped)", browserdata)
            return BrowserCheckResult.TAMPERED

    browsers = {"webkit", "firefox", "chromium"}

    base_seed = bytearray((browserdata["t2"] & 0xFFFF_FFFF).to_bytes(4, "big"))
    base_seed[0] ^= browserdata["s"] >> 8
    base_seed[1] ^= browserdata["s"] & 0xFF
    base_seed[2] ^= browserdata["s"] >> 8
    base_seed[3] ^= browserdata["s"] & 0xFF

    key = crc32(bytes([x ^ 181 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["m1"])
    if decoded is None:
        print("m1 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("m1", decrypted)
    if decrypted == b"1.9275814160560204e-50":
        browsers &= {"chromium"}
    elif decrypted == b"1.9275814160560206e-50":
        browsers &= {"webkit", "firefox"}
    else:
        print("invalid m1 value", decrypted)
        return BrowserCheckResult.SUSPICIOUS

    key = crc32(bytes([x ^ 40 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["m2"])
    if decoded is None:
        print("m2 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("m2", decrypted)
    if decrypted == b"1.046919966902314e+308":
        browsers &= {"firefox"}
    elif decrypted == b"1.0469199669023138e+308":
        browsers &= {"webkit", "chromium"}
    else:
        print("invalid m2 value", decrypted)
        return BrowserCheckResult.SUSPICIOUS

    if not browsers:
        print("conflicting math results")
        return BrowserCheckResult.SUSPICIOUS

    print("possible browsers", browsers)

    has_sec_fetch = "webkit" not in browsers

    if (
        has_sec_fetch
        and request.headers.keys() & SEC_FETCH_HEADERS != SEC_FETCH_HEADERS
    ):
        print(
            "request does not have all required sec-fetch-* headers",
            browsers,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED
    elif not has_sec_fetch and request.headers.keys() & SEC_FETCH_HEADERS:
        print(
            "request should not have sec-fetch-* headers",
            browsers,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED

    has_sec_ch_ua = "chromium" in browsers

    if (
        has_sec_ch_ua
        and request.headers.keys() & SEC_CH_UA_HEADERS != SEC_CH_UA_HEADERS
    ):
        print(
            "request does not have all required sec-ch-ua-* headers",
            browsers,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED
    elif not has_sec_ch_ua and request.headers.keys() & SEC_CH_UA_HEADERS:
        print(
            "request should not have sec-ch-ua-* headers",
            browsers,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED

    key = crc32(bytes([x ^ 149 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["p1"])
    if decoded is None:
        print("p1 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("p1", decrypted)
    try:
        platform = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid p1 value", decrypted)
        return BrowserCheckResult.TAMPERED

    if has_sec_ch_ua:
        sec_ch_ua_platform = (
            request.headers["sec-ch-ua-platform"]
            .lower()
            .replace(" ", "")
            .replace('"', "")
        )
        platform_map = {"macos": "mac", "windows": "win"}
        sec_ch_ua_platform = platform_map.get(sec_ch_ua_platform, sec_ch_ua_platform)
        if sec_ch_ua_platform not in platform.lower():
            print(
                "platform in sec-ch-ua-platform header does not match",
                platform,
                sec_ch_ua_platform,
            )
            return BrowserCheckResult.TAMPERED

    key = crc32(bytes([x ^ 67 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l1"])
    if decoded is None:
        print("l1 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l1", decrypted)
    try:
        url = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l1 value", decrypted)
        return BrowserCheckResult.TAMPERED

    key = crc32(bytes([x ^ 114 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l2"])
    if decoded is None:
        print("l2 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l2", decrypted)
    try:
        locale = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l2 value", decrypted)
        return BrowserCheckResult.TAMPERED

    accept_language = request.headers.get("accept-language")
    if accept_language is None or locale not in accept_language:
        print("invalid lcoale", locale, accept_language)
        return BrowserCheckResult.TAMPERED

    key = crc32(bytes([x ^ 184 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l3"])
    if decoded is None:
        print("l3 is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l3", decrypted)
    try:
        intl_check = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l3 value", decrypted)
        return BrowserCheckResult.TAMPERED

    if intl_check.count("|") != 1:
        print("invalid l3 | count", intl_check)
        return BrowserCheckResult.TAMPERED
    # firefox seems to have issues with this
    elif (
        intl_check.split("|")[0] != intl_check.split("|")[1]
        and "firefox" not in browsers
    ):
        print("invalid l3 values", intl_check)
        return BrowserCheckResult.SUSPICIOUS

    key = crc32(bytes([x ^ 84 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["f"])
    if decoded is None:
        print("f is not valid base64", browserdata)
        return BrowserCheckResult.TAMPERED
    offset = 0
    fonts = set()
    while offset < len(decoded):
        length = decoded[offset] ^ 15 ^ key[3]
        decrypted = bytes(
            [
                x ^ key[(offset + 1 + i) % 4]
                for i, x in enumerate(decoded[offset + 1 : offset + 1 + length])
            ]
        )
        offset += 1 + length
        try:
            font = decrypted.decode()
        except UnicodeDecodeError:
            print("invalid f value", length, decrypted)
            return BrowserCheckResult.TAMPERED
        fonts.add(font)
    print("f", fonts)
    if fonts & APPLE_FONTS:
        if not platform.startswith("iP") and not platform.startswith("Mac"):
            print("apple fonts, but not apple platform", platform)
            return BrowserCheckResult.TAMPERED

    elif fonts & WINDOWS_FONTS:
        if not platform.startswith("Win"):
            print("windows fonts, but not windows platform", platform)
            return BrowserCheckResult.TAMPERED

    elif fonts & LINUX_FONTS:
        if not platform.startswith("Linux"):
            print("linux fonts, but not linux platform", platform)
            return BrowserCheckResult.TAMPERED

    else:
        print("unknown platform for fonts")
        return BrowserCheckResult.SUSPICIOUS

    return BrowserCheckResult.OK


class BrowserData(typing.TypedDict):
    t1: int
    t2: int
    s: int
    m1: str
    m2: str
    p1: str
    l1: str
    l2: str
    l3: str
    f: str
