from __future__ import annotations

import enum
import typing
from binascii import crc32
from datetime import datetime

from sanic import Request

from .based import b64parse


class BrowserCheckResult(enum.Enum):
    OK = 0
    SUSPICIOUS = 1
    TAMPERED = 2
    BAD_REQUEST = 3
    AUTOMATED = 4


class Browser(enum.Enum):
    WEBKIT = enum.auto()
    CHROMIUM = enum.auto()
    FIREFOX = enum.auto()
    UNKNOWN = enum.auto()


class Platform(enum.Enum):
    ANDROID = enum.auto()
    IOS = enum.auto()
    MAC = enum.auto()
    LINUX = enum.auto()
    WINDOWS = enum.auto()
    UNKNOWN = enum.auto()


SEC_FETCH_BROWSERS = {Browser.FIREFOX, Browser.CHROMIUM}
SEC_FETCH_HEADERS = {"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"}
SEC_CH_UA_BROWSERS = {Browser.CHROMIUM}
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


def browser_check(
    request: Request, browserdata: BrowserData
) -> tuple[BrowserCheckResult, bytes]:
    # check if payload makes sense
    browserdata_shape = {
        k: typing.ForwardRef(type(v).__name__) for k, v in browserdata.items()
    }
    # using a string compare cuz everything else just does not work
    if str(browserdata_shape) != str(BrowserData.__annotations__):
        print("shape of browserdata does not match", browserdata_shape, browserdata)
        return BrowserCheckResult.BAD_REQUEST, b""

    time_valid = check_time(browserdata)
    sequence_valid = check_sequence(browserdata)
    if (
        time_valid == BrowserCheckResult.TAMPERED
        or sequence_valid == BrowserCheckResult.TAMPERED
    ):
        return BrowserCheckResult.BAD_REQUEST, b""

    base_seed = bytearray((browserdata["t2"] & 0xFFFF_FFFF).to_bytes(4, "big"))
    base_seed[0] ^= browserdata["s"] >> 8
    base_seed[1] ^= browserdata["s"] & 0xFF
    base_seed[2] ^= browserdata["s"] >> 8
    base_seed[3] ^= browserdata["s"] & 0xFF

    math_result, browser = check_math(browserdata, base_seed)
    browser_headers_result = check_browser_headers(request, browser)
    platform_result, platform = check_platform(browserdata, base_seed)
    platform_ch_result = check_platform_ch(request, browser, platform)
    url_result, url = check_url(browserdata, base_seed)
    locale_result, locale = check_locale(browserdata, base_seed, request)
    locale_spoof_result, locale_spoof = check_locale_spoof(
        browserdata, base_seed, browser
    )
    fonts_result, fonts = check_fonts(browserdata, base_seed, platform)
    rtt_result = check_connection_rtt(browserdata, base_seed)
    browser_engine_result = check_browser_engine(browserdata, base_seed, browser)
    detections_result = check_detections(browserdata, base_seed, browser)

    fingerprint = b"\x00".join(
        [
            browserdata["t1"].to_bytes(8, "big"),
            browser.name.encode(),
            platform.name.encode(),
            url,
            locale,
            locale_spoof,
            *map(str.encode, fonts),
        ]
    )
    results = [
        math_result,
        browser_headers_result,
        platform_result,
        platform_ch_result,
        url_result,
        locale_result,
        locale_spoof_result,
        fonts_result,
        rtt_result,
        browser_engine_result,
        detections_result,
    ]

    return max(results, key=lambda x: x.value), fingerprint


def check_time(browserdata: BrowserData) -> BrowserCheckResult:
    # check if the values make sense
    if browserdata["t1"] >= browserdata["t2"]:
        print("current before page load", browserdata)
        return BrowserCheckResult.TAMPERED
    elif browserdata["t2"] > browserdata["t3"]:
        print("submit before current", browserdata)
        return BrowserCheckResult.TAMPERED

    expected_tc = (
        browserdata["t1"] ^ browserdata["t2"] ^ browserdata["t3"] ^ browserdata["s"]
    ) & 0xFFFF
    if expected_tc != browserdata["tc"]:
        print("incorrect tc", browserdata, expected_tc)
        return BrowserCheckResult.TAMPERED

    time_delta = abs(browserdata["t2"] - datetime.now().timestamp() * 1000)
    if time_delta > 60_000:
        print("time delta too large", time_delta, browserdata)
        return BrowserCheckResult.SUSPICIOUS

    return BrowserCheckResult.OK


def check_sequence(browserdata: BrowserData) -> BrowserCheckResult:
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

    return BrowserCheckResult.OK


def check_math(
    browserdata: BrowserData, base_seed: bytes
) -> tuple[BrowserCheckResult, Browser]:
    key_m1 = crc32(bytes([x ^ 181 for x in base_seed])).to_bytes(4, "big")
    decoded_m1 = b64parse(browserdata["m1"])
    if decoded_m1 is None:
        print("m1 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, Browser.UNKNOWN
    m1 = bytes([x ^ key_m1[i % 4] for i, x in enumerate(decoded_m1)])

    key_m2 = crc32(bytes([x ^ 40 for x in base_seed])).to_bytes(4, "big")
    decoded_m2 = b64parse(browserdata["m2"])
    if decoded_m2 is None:
        print("m2 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, Browser.UNKNOWN
    m2 = bytes([x ^ key_m2[i % 4] for i, x in enumerate(decoded_m2)])

    browsers = {Browser.WEBKIT, Browser.CHROMIUM, Browser.FIREFOX}
    if m1 == b"1.9275814160560204e-50":
        browsers &= {Browser.CHROMIUM}
    elif m1 == b"1.9275814160560206e-50":
        browsers &= {Browser.WEBKIT, Browser.FIREFOX}
    else:
        print("invalid m1 value", m1)
        return BrowserCheckResult.SUSPICIOUS, Browser.UNKNOWN

    if m2 == b"1.046919966902314e+308":
        browsers &= {Browser.FIREFOX}
    elif m2 == b"1.0469199669023138e+308":
        browsers &= {Browser.WEBKIT, Browser.CHROMIUM}
    else:
        print("invalid m2 value", m2)
        return BrowserCheckResult.SUSPICIOUS, Browser.UNKNOWN

    if len(browsers) != 1:
        print("conflicting math results", browsers)
        return BrowserCheckResult.SUSPICIOUS, Browser.UNKNOWN

    (browser,) = browsers
    return BrowserCheckResult.OK, browser


def check_browser_headers(request: Request, browser: Browser) -> BrowserCheckResult:
    has_sec_fetch = browser in SEC_FETCH_BROWSERS

    if (
        has_sec_fetch
        and request.headers.keys() & SEC_FETCH_HEADERS != SEC_FETCH_HEADERS
    ):
        print(
            "request does not have all required sec-fetch-* headers",
            browser,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED
    elif not has_sec_fetch and request.headers.keys() & SEC_FETCH_HEADERS:
        print(
            "request should not have sec-fetch-* headers",
            browser,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED

    has_sec_ch_ua = browser in SEC_CH_UA_BROWSERS

    if (
        has_sec_ch_ua
        and request.headers.keys() & SEC_CH_UA_HEADERS != SEC_CH_UA_HEADERS
    ):
        print(
            "request does not have all required sec-ch-ua-* headers",
            browser,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED
    elif not has_sec_ch_ua and request.headers.keys() & SEC_CH_UA_HEADERS:
        print(
            "request should not have sec-ch-ua-* headers",
            browser,
            tuple(request.headers.keys()),
        )
        return BrowserCheckResult.TAMPERED

    return BrowserCheckResult.OK


def check_platform(
    browserdata: BrowserData, base_seed: bytes
) -> tuple[BrowserCheckResult, Platform]:
    key = crc32(bytes([x ^ 149 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["p1"])
    if decoded is None:
        print("p1 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, Platform.UNKNOWN
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("p1", decrypted)
    try:
        platform = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid p1 value", decrypted)
        return BrowserCheckResult.TAMPERED, Platform.UNKNOWN

    if platform.startswith("iP"):
        return BrowserCheckResult.OK, Platform.IOS
    elif platform.startswith("Mac"):
        return BrowserCheckResult.OK, Platform.MAC
    elif platform.startswith("Linux"):
        return BrowserCheckResult.OK, Platform.LINUX
    elif platform.startswith("Win"):
        return BrowserCheckResult.OK, Platform.WINDOWS
    return BrowserCheckResult.OK, Platform.UNKNOWN


def check_platform_ch(
    request: Request, browser: Browser, platform: Platform
) -> BrowserCheckResult:
    if browser not in SEC_CH_UA_BROWSERS:
        return BrowserCheckResult.OK  # N/A

    ch_platform_header = (
        request.headers.get("sec-ch-ua-platform", "").replace('"', "").replace("'", "")
    )
    match ch_platform_header:
        case "Android":
            ch_platform = Platform.ANDROID
        case "iOS":
            ch_platform = Platform.IOS
        case "Linux":
            ch_platform = Platform.LINUX
        case "macOS":
            ch_platform = Platform.MAC
        case "Windows":
            ch_platform = Platform.WINDOWS
        case _:
            ch_platform = Platform.UNKNOWN

    if ch_platform != platform:
        print(
            "platform in sec-ch-ua-platform header does not match",
            platform,
            ch_platform,
            ch_platform_header,
        )
        return BrowserCheckResult.SUSPICIOUS

    return BrowserCheckResult.OK


def check_url(
    browserdata: BrowserData, base_seed: bytes
) -> tuple[BrowserCheckResult, bytes]:
    key = crc32(bytes([x ^ 67 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l1"])
    if decoded is None:
        print("l1 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, b""
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l1", decrypted)
    try:
        url = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l1 value", decrypted)
        return BrowserCheckResult.TAMPERED, decrypted

    return BrowserCheckResult.OK, url.encode()


def check_locale(
    browserdata: BrowserData, base_seed: bytes, request: Request
) -> tuple[BrowserCheckResult, bytes]:
    key = crc32(bytes([x ^ 114 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l2"])
    if decoded is None:
        print("l2 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, b""
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l2", decrypted)
    try:
        locale = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l2 value", decrypted)
        return BrowserCheckResult.TAMPERED, decrypted

    accept_language = request.headers.get("accept-language")
    if accept_language is None or locale not in accept_language:
        print("invalid locale", locale, accept_language)
        return BrowserCheckResult.TAMPERED, locale.encode()

    return BrowserCheckResult.OK, locale.encode()


def check_locale_spoof(
    browserdata: BrowserData, base_seed: bytes, browser: Browser
) -> tuple[BrowserCheckResult, bytes]:
    key = crc32(bytes([x ^ 184 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["l3"])
    if decoded is None:
        print("l3 is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, b""
    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    print("l3", decrypted)
    try:
        intl_check = decrypted.decode()
    except UnicodeDecodeError:
        print("invalid l3 value", decrypted)
        return BrowserCheckResult.TAMPERED, decrypted

    if intl_check.count("|") != 1:
        print("invalid l3 | count", intl_check)
        return BrowserCheckResult.TAMPERED, intl_check.encode()
    # firefox seems to have issues with this
    elif (
        intl_check.split("|")[0] != intl_check.split("|")[1]
        and browser != Browser.FIREFOX
    ):
        print("invalid l3 values", intl_check)
        return BrowserCheckResult.SUSPICIOUS, intl_check.encode()

    return BrowserCheckResult.OK, intl_check.encode()


def check_fonts(
    browserdata: BrowserData, base_seed: bytes, platform: Platform
) -> tuple[BrowserCheckResult, set[str]]:
    key = crc32(bytes([x ^ 84 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["f"])
    if decoded is None:
        print("f is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST, set()

    offset = 0
    fonts = set()
    while offset < len(decoded):
        length = decoded[offset] ^ 15 ^ key[3]
        # this can be used for fingerprinting in the future
        font_checksum = int.from_bytes(
            bytes(
                [x ^ key[i % 4] for i, x in enumerate(decoded[offset + 1 : offset + 5])]
            ),
            "big",
        )
        decrypted = bytes(
            [
                x ^ key[(offset + 5 + i) % 4]
                for i, x in enumerate(decoded[offset + 5 : offset + 5 + length])
            ]
        )
        offset += 5 + length
        try:
            font = decrypted.decode()
        except UnicodeDecodeError:
            print("invalid f value", length, font_checksum, decrypted)
            return BrowserCheckResult.TAMPERED, set()
        fonts.add(font)

    print("f", fonts)
    if fonts & APPLE_FONTS:
        if platform not in {Platform.MAC, Platform.IOS}:
            print("apple fonts, but not apple platform", platform)
            return BrowserCheckResult.TAMPERED, fonts

    elif fonts & WINDOWS_FONTS:
        if platform != Platform.WINDOWS:
            print("windows fonts, but not windows platform", platform)
            return BrowserCheckResult.TAMPERED, fonts

    elif fonts & LINUX_FONTS:
        if platform != Platform.LINUX:
            print("linux fonts, but not linux platform", platform)
            return BrowserCheckResult.TAMPERED, fonts

    else:
        print("unknown platform for fonts")
        return BrowserCheckResult.SUSPICIOUS, fonts

    return BrowserCheckResult.OK, fonts


def check_connection_rtt(
    browserdata: BrowserData, base_seed: bytes
) -> BrowserCheckResult:
    key = crc32(bytes([x ^ 155 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["r"])
    if decoded is None:
        print("r is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST
    rtt = decoded[1] ^ key[3]
    if rtt == 0:
        return BrowserCheckResult.SUSPICIOUS
    return BrowserCheckResult.OK


def check_browser_engine(
    browserdata: BrowserData, base_seed: bytes, browser: Browser
) -> BrowserCheckResult:
    key = crc32(bytes([x ^ 71 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["e"])
    if decoded is None:
        print("e is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST

    decrypted = bytes([x ^ key[i % 4] for i, x in enumerate(decoded)])
    tofixed_length = decoded[0] ^ key[2]
    print("e", decrypted, tofixed_length)

    tofixed_data = decrypted[1 : 1 + tofixed_length]

    match tofixed_data:
        case b"toFixed() digits argument must be between 0 and 100":
            tofixed_browser = Browser.CHROMIUM  # V8
        case b"precision -1 out of range":
            tofixed_browser = Browser.FIREFOX  # SpiderMonkey
        case b"toFixed() argument must be between 0 and 100":
            tofixed_browser = Browser.WEBKIT  # JavaScriptCore
        case _:
            print("unknown engine", tofixed_data)
            return BrowserCheckResult.SUSPICIOUS

    if tofixed_browser != browser:
        print(
            "mismatching engine browser and actual",
            tofixed_browser,
            browser,
            tofixed_data,
        )
        return BrowserCheckResult.TAMPERED

    native_data = decrypted[1 + tofixed_length :]
    match native_data:
        case b"function () { [native code] }":
            native_browser = {Browser.CHROMIUM}
        case b"function () {\n    [native code]\n}":
            native_browser = {Browser.WEBKIT, Browser.FIREFOX}
        case _:
            print("unknown engine", native_data)
            return BrowserCheckResult.SUSPICIOUS

    if browser not in native_browser:
        print(
            "mismatching engine browser and actual",
            native_browser,
            browser,
            native_data,
        )
        return BrowserCheckResult.TAMPERED

    return BrowserCheckResult.OK


def check_detections(
    browserdata: BrowserData, base_seed: bytes, browser: Browser
) -> BrowserCheckResult:
    key = crc32(bytes([x ^ 142 for x in base_seed])).to_bytes(4, "big")
    decoded = b64parse(browserdata["k"])
    if decoded is None:
        print("k is not valid base64", browserdata)
        return BrowserCheckResult.BAD_REQUEST
    elif len(decoded) % 2 == 1 or len(decoded) < 20:
        print("k has incorrect length", len(decoded), decoded, browserdata)
        return BrowserCheckResult.BAD_REQUEST

    decrypted = bytes([x ^ key[i % 4] ^ i & 0xFF for i, x in enumerate(decoded)])
    browsers = {Browser.CHROMIUM, Browser.WEBKIT, Browser.FIREFOX}
    for i in range(0, len(decrypted), 2):
        detection = int.from_bytes(decrypted[i : i + 2], "big")
        category = detection >> 12
        match category:
            case 0:  # filler
                pass
            case 1 | 2:  # webdriver
                print("failed webdriver check", detection)
                return BrowserCheckResult.AUTOMATED
            case 3:  # browser check
                match detection:
                    case 0x3000 | 0x3001:
                        browsers &= {Browser.CHROMIUM}
                    case 0x3002:
                        browsers &= {Browser.FIREFOX}
                    case 0x3003:
                        browsers &= {Browser.WEBKIT}
                    case _:
                        print("unknown brower check", detection, hex(detection))
                        return BrowserCheckResult.TAMPERED
            case _:
                print("unknown detection", detection)
                return BrowserCheckResult.TAMPERED

    if len(browsers) != 1:
        print("unable to identify browser", browsers)
        return BrowserCheckResult.SUSPICIOUS

    (expected_browser,) = browsers
    if browser != expected_browser:
        print("browser mismatch", expected_browser, browser)
        return BrowserCheckResult.SUSPICIOUS

    return BrowserCheckResult.OK


class BrowserData(typing.TypedDict):
    t1: int
    t2: int
    t3: int
    tc: int
    s: int
    m1: str
    m2: str
    p1: str
    l1: str
    l2: str
    l3: str
    f: str
    r: str
    e: str
    k: str
