import enum
import time
import typing
from binascii import crc32

from sanic import Request


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


class BrowserData(typing.TypedDict):
    picasso: str
    detections: str
    localestring: str
    math_pow: str
    math_sinh: str
    time: str
    engine: str
    fonts: str
    navigator_webdriver: bool
    navigator_language: str
    navigator_platform: str
    document_location: str
    token: str


def browser_check(
    request: Request, browserdata: BrowserData
) -> tuple[BrowserCheckResult, bytes, int]:
    # check if payload makes sense
    browserdata_shape = {k: type(v) for k, v in browserdata.items()}
    # using a string compare cuz everything else just does not work
    if browserdata_shape != BrowserData.__annotations__:
        print("shape of browserdata does not match", browserdata_shape, browserdata)
        return BrowserCheckResult.BAD_REQUEST, b"", 0

    time_result = check_time(browserdata)
    math_result, browser = check_math(browserdata)
    browser_headers_result = check_browser_headers(request, browser)
    platform_result, platform = check_platform(browserdata)
    platform_ch_result = check_platform_ch(request, browser, platform)
    url_result, url = check_url(browserdata)
    locale_result, locale = check_locale(browserdata, request)
    locale_spoof_result, locale_spoof = check_locale_spoof(browserdata, browser)
    fonts_result, fonts = check_fonts(browserdata, platform)
    browser_engine_result = check_browser_engine(browserdata, browser)
    detections_result = check_detections(browserdata, browser)
    picasso_result, picasso_fingerprint = check_picasso(browserdata)

    fingerprint = b"\x00".join(
        [
            browser.name.encode(),
            platform.name.encode(),
            url,
            locale,
            locale_spoof,
            picasso_fingerprint.to_bytes(4, "big"),
            *map(str.encode, fonts),
        ]
    )

    results = [
        time_result,
        math_result,
        browser_headers_result,
        platform_result,
        platform_ch_result,
        url_result,
        locale_result,
        locale_spoof_result,
        fonts_result,
        browser_engine_result,
        detections_result,
        picasso_result,
    ]

    return max(results, key=lambda x: x.value), fingerprint, picasso_fingerprint


def check_time(browserdata: BrowserData) -> BrowserCheckResult:
    if not browserdata["time"].isdigit():
        print("time is not an integer", browserdata["time"])
        return BrowserCheckResult.BAD_REQUEST

    time_delta = abs(int(browserdata["time"]) - time.time() * 1000)
    if time_delta > 60_000:
        print("time delta too large", time_delta, browserdata)
        return BrowserCheckResult.SUSPICIOUS

    return BrowserCheckResult.OK


def check_math(browserdata: BrowserData) -> tuple[BrowserCheckResult, Browser]:
    browsers = {Browser.WEBKIT, Browser.CHROMIUM, Browser.FIREFOX}
    if browserdata["math_pow"] == "1.9275814160560204e-50":
        browsers &= {Browser.CHROMIUM}
    elif browserdata["math_pow"] == "1.9275814160560206e-50":
        browsers &= {Browser.WEBKIT, Browser.FIREFOX}
    else:
        print("invalid m1 value", browserdata["math_pow"])
        return BrowserCheckResult.SUSPICIOUS, Browser.UNKNOWN

    if browserdata["math_sinh"] == "1.046919966902314e+308":
        browsers &= {Browser.FIREFOX}
    elif browserdata["math_sinh"] == "1.0469199669023138e+308":
        browsers &= {Browser.WEBKIT, Browser.CHROMIUM}
    else:
        print("invalid m2 value", browserdata["math_sinh"])
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


def check_platform(browserdata: BrowserData) -> tuple[BrowserCheckResult, Platform]:
    platform = browserdata["navigator_platform"]
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


def check_url(browserdata: BrowserData) -> tuple[BrowserCheckResult, bytes]:
    return BrowserCheckResult.OK, browserdata["document_location"].encode()


def check_locale(
    browserdata: BrowserData, request: Request
) -> tuple[BrowserCheckResult, bytes]:
    locale = browserdata["navigator_language"]
    accept_language = request.headers.get("accept-language")
    if accept_language is None or locale not in accept_language:
        print("invalid locale", locale, accept_language)
        return BrowserCheckResult.TAMPERED, locale.encode()

    return BrowserCheckResult.OK, locale.encode()


def check_locale_spoof(
    browserdata: BrowserData, browser: Browser
) -> tuple[BrowserCheckResult, bytes]:
    intl_check = browserdata["localestring"]
    if intl_check.count("|") != 1:
        print("invalid localestring | count", intl_check)
        return BrowserCheckResult.TAMPERED, intl_check.encode()
    # firefox seems to have issues with this
    elif (
        intl_check.split("|")[0] != intl_check.split("|")[1]
        and browser != Browser.FIREFOX
    ):
        print("invalid localestring values", intl_check)
        return BrowserCheckResult.SUSPICIOUS, intl_check.encode()

    return BrowserCheckResult.OK, intl_check.encode()


def check_fonts(
    browserdata: BrowserData, platform: Platform
) -> tuple[BrowserCheckResult, set[str]]:
    fonts = set(browserdata["fonts"].split("|")[:-1])
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


def check_browser_engine(
    browserdata: BrowserData, browser: Browser
) -> BrowserCheckResult:
    if browserdata["engine"].count("|") != 1:
        print("browser engine value is spoofed", browserdata["engine"])
        return BrowserCheckResult.TAMPERED

    tofixed_data, native_data = browserdata["engine"].split("|")

    match tofixed_data:
        case "toFixed() digits argument must be between 0 and 100":
            tofixed_browser = Browser.CHROMIUM  # V8
        case "precision -1 out of range":
            tofixed_browser = Browser.FIREFOX  # SpiderMonkey
        case "toFixed() argument must be between 0 and 100":
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

    match native_data:
        case "function () { [native code] }":
            native_browser = {Browser.CHROMIUM}
        case "function () {\n    [native code]\n}":
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


def check_detections(browserdata: BrowserData, browser: Browser) -> BrowserCheckResult:
    try:
        all_detections = list(map(int, browserdata["detections"].split(",")[:-1]))
    except ValueError:
        print("detections contains non-int", browserdata["detections"])
        return BrowserCheckResult.TAMPERED

    browsers = {Browser.CHROMIUM, Browser.WEBKIT, Browser.FIREFOX}
    detections = []
    results: list[BrowserCheckResult] = []
    for detection in all_detections:
        category = detection >> 12
        if category:
            detections.append(hex(category)[2:].zfill(4))
        match category:
            case 0:  # filler
                pass
            case 1:  # automated browser
                # 10xx undetected-chromedriver
                #   00 window.objectToInspect
                # 11xx playwright
                #   00 chromium (oncontentvisibilityautostatechanged)
                #   02 webkit (onorientationchange)
                # 1Axx stealth scripts
                #   00 "utils" in scope
                #   01 userAgent property
                #   02 webdriver property
                #   03 webdriver=undefined
                #   04 webdriver != false (safari & firefox)
                #   05 toString proxy (only firefox)
                # 1Exx plugins
                #   00 nopecha (recaptcha auto open trap)
                #   01 nopecha (aws auto open trap)
                # 1Fxx generic
                #   00 something in window ending with `_Symbol`
                #   01 something in iframe window ending with `_Symbol`
                #   02 navigator.webdriver is truthy
                print("failed automated browser check", hex(detection)[2:].zfill(4))
                results.append(BrowserCheckResult.AUTOMATED)
            case 2:  # suspicious stuff
                # 0000 pdf disabled
                results.append(BrowserCheckResult.SUSPICIOUS)
            case 3:  # browser check
                match detection:
                    case 0x3000 | 0x3001:
                        browsers &= {Browser.CHROMIUM}
                    case 0x3002 | 0x3003 | 0x3005:
                        browsers &= {Browser.FIREFOX}
                    case 0x3004:
                        browsers &= {Browser.WEBKIT}
                    case _:
                        print("unknown brower check", hex(detection)[2:].zfill(4))
                        results.append(BrowserCheckResult.TAMPERED)
            case _:
                print("unknown detection", hex(detection)[2:].zfill(4))
                results.append(BrowserCheckResult.TAMPERED)

    if len(browsers) != 1:
        print("unable to identify browser", browsers)
        results.append(BrowserCheckResult.SUSPICIOUS)
    else:
        (expected_browser,) = browsers
        if browser != expected_browser:
            print("browser mismatch", expected_browser, browser)
            results.append(BrowserCheckResult.SUSPICIOUS)

    if results:
        return max(results, key=lambda x: x.value)

    return BrowserCheckResult.OK


def check_picasso(browserdata: BrowserData) -> tuple[BrowserCheckResult, int]:
    if len(browserdata["picasso"]) != 24 or not all(
        x in "0123456789abcdef" for x in browserdata["picasso"]
    ):
        print("picasso has incorrect length/values", browserdata["picasso"])
        return BrowserCheckResult.TAMPERED, 0

    picasso = bytes.fromhex(browserdata["picasso"])

    rkey = int.from_bytes(picasso[:4], "big") ^ 0xD0BED0AA
    fp = int.from_bytes(picasso[4:8], "big") ^ rkey
    checksum = int.from_bytes(picasso[8:], "big") ^ 0xFBE2088E

    expected_checksum = crc32(picasso[:8])
    if expected_checksum != checksum:
        print("picasso has incorrect checksum", fp, checksum, expected_checksum)
        return BrowserCheckResult.TAMPERED, 0

    return BrowserCheckResult.OK, fp
