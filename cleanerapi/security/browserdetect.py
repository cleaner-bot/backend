import enum
import time
import typing
from binascii import crc32

from sanic import Request


class BrowserCheckVerdict(enum.Enum):
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


class BrowserCheckResult(typing.NamedTuple):
    verdict: BrowserCheckVerdict
    browser: Browser | None | None = None
    platform: Platform | None | None = None
    reason: str | None = None


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
    "Galvji",
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
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.BAD_REQUEST, reason="Invalid request shape"
            ),
            b"",
            0,
        )

    time_result = check_time(browserdata)
    math_result = check_math(browserdata)
    browser_headers_result = check_browser_headers(request)
    platform_result = check_platform(browserdata)
    platform_ch_result = check_platform_ch(request)
    url_result, url = check_url(browserdata)
    locale_result, locale = check_locale(browserdata, request)
    assert math_result.browser
    locale_spoof_result, locale_spoof = check_locale_spoof(
        browserdata, math_result.browser
    )
    fonts_result, fonts = check_fonts(browserdata)
    detections_result = check_detections(browserdata)
    browser_engine_result = check_browser_engine(browserdata)
    picasso_result, picasso_fingerprint = check_picasso(browserdata)

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

    browsers = set(x.browser for x in results if x.browser)
    if len(browsers) == 1:
        (browser,) = browsers
    else:
        browser = Browser.UNKNOWN

    platforms = set(x.platform for x in results if x.platform)
    if len(browsers) == 1:
        (platform,) = platforms
    else:
        platform = Platform.UNKNOWN

    print(browsers, platforms)

    if browser == Browser.UNKNOWN:
        results.append(
            BrowserCheckResult(
                BrowserCheckVerdict.SUSPICIOUS, reason="Conflicting browser results"
            )
        )
    if platform == Platform.UNKNOWN:
        results.append(
            BrowserCheckResult(
                BrowserCheckVerdict.SUSPICIOUS, reason="Conflicting platform results"
            )
        )

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

    return max(results, key=lambda x: x.verdict.value), fingerprint, picasso_fingerprint


def check_time(browserdata: BrowserData) -> BrowserCheckResult:
    if not browserdata["time"].isdigit():
        print("time is not an integer", browserdata["time"])
        return BrowserCheckResult(
            BrowserCheckVerdict.BAD_REQUEST, reason="Time is not an integer"
        )

    time_delta = abs(int(browserdata["time"]) - time.time() * 1000)
    if time_delta > 60_000:
        print("time delta too large", time_delta, browserdata)
        return BrowserCheckResult(
            BrowserCheckVerdict.SUSPICIOUS, reason="Request too old"
        )

    return BrowserCheckResult(BrowserCheckVerdict.OK)


def check_math(browserdata: BrowserData) -> BrowserCheckResult:
    browsers = {Browser.WEBKIT, Browser.CHROMIUM, Browser.FIREFOX}
    if browserdata["math_pow"] == "1.9275814160560204e-50":
        browsers &= {Browser.CHROMIUM}
    elif browserdata["math_pow"] == "1.9275814160560206e-50":
        browsers &= {Browser.WEBKIT, Browser.FIREFOX}
    else:
        print("invalid math_pow value", browserdata["math_pow"])
        return BrowserCheckResult(
            BrowserCheckVerdict.BAD_REQUEST,
            browser=Browser.UNKNOWN,
            reason="Invalid math_pow",
        )

    if browserdata["math_sinh"] == "1.046919966902314e+308":
        browsers &= {Browser.FIREFOX}
    elif browserdata["math_sinh"] == "1.0469199669023138e+308":
        browsers &= {Browser.WEBKIT, Browser.CHROMIUM}
    else:
        print("invalid math_sinh value", browserdata["math_sinh"])
        return BrowserCheckResult(
            BrowserCheckVerdict.SUSPICIOUS,
            browser=Browser.UNKNOWN,
            reason="Invalid math_sinh",
        )

    if len(browsers) != 1:
        print("conflicting math results", browsers)
        return BrowserCheckResult(
            BrowserCheckVerdict.SUSPICIOUS,
            browser=Browser.UNKNOWN,
            reason="Conflicting math results",
        )

    (browser,) = browsers
    return BrowserCheckResult(BrowserCheckVerdict.OK, browser=browser)


def check_browser_headers(request: Request) -> BrowserCheckResult:
    if request.headers.keys() & SEC_CH_UA_HEADERS != SEC_CH_UA_HEADERS:
        return BrowserCheckResult(BrowserCheckVerdict.OK, Browser.CHROMIUM)
    elif request.headers.keys() & SEC_FETCH_HEADERS != SEC_FETCH_HEADERS:
        return BrowserCheckResult(BrowserCheckVerdict.OK, Browser.FIREFOX)

    return BrowserCheckResult(BrowserCheckVerdict.OK, Browser.WEBKIT)


def check_platform(browserdata: BrowserData) -> BrowserCheckResult:
    platform = browserdata["navigator_platform"]
    if platform.startswith("iP"):
        return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.IOS)
    elif platform.startswith("Mac"):
        return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.MAC)
    elif platform.startswith("Linux"):
        return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.LINUX)
    elif platform.startswith("Win"):
        return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.WINDOWS)
    return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.UNKNOWN)


def check_platform_ch(request: Request) -> BrowserCheckResult:
    if "sec-ch-ua-platform" not in request.headers:
        return BrowserCheckResult(BrowserCheckVerdict.OK)
    ch_platform_header = (
        request.headers.get("sec-ch-ua-platform", "").replace('"', "").replace("'", "")
    )

    match ch_platform_header:
        case "Android":
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.ANDROID)
        case "iOS":
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.IOS)
        case "Linux":
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.LINUX)
        case "macOS":
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.MAC)
        case "Windows":
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.WINDOWS)
        case _:
            return BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.UNKNOWN)


def check_url(browserdata: BrowserData) -> tuple[BrowserCheckResult, bytes]:
    return (
        BrowserCheckResult(BrowserCheckVerdict.OK),
        browserdata["document_location"].encode(),
    )


def check_locale(
    browserdata: BrowserData, request: Request
) -> tuple[BrowserCheckResult, bytes]:
    locale = browserdata["navigator_language"]
    accept_language = request.headers.get("accept-language")
    if accept_language is None or locale not in accept_language:
        print("invalid locale", locale, accept_language)
        return (
            BrowserCheckResult(BrowserCheckVerdict.TAMPERED, reason="Invalid locale"),
            locale.encode(),
        )

    return BrowserCheckResult(BrowserCheckVerdict.OK), locale.encode()


def check_locale_spoof(
    browserdata: BrowserData, browser: Browser
) -> tuple[BrowserCheckResult, bytes]:
    intl_check = browserdata["localestring"]
    if intl_check.count("|") != 1:
        print("invalid localestring | count", intl_check)
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.TAMPERED, reason="Invalid localestring"
            ),
            intl_check.encode(),
        )
    # firefox seems to have issues with this
    elif (
        intl_check.split("|")[0] != intl_check.split("|")[1]
        and browser != Browser.FIREFOX
    ):
        print("invalid localestring values", intl_check)
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.SUSPICIOUS, reason="Mismatching localestring"
            ),
            intl_check.encode(),
        )

    return BrowserCheckResult(BrowserCheckVerdict.OK), intl_check.encode()


def check_fonts(browserdata: BrowserData) -> tuple[BrowserCheckResult, set[str]]:
    fonts = set(browserdata["fonts"].split("|")[:-1])
    if fonts & APPLE_FONTS:
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.OK,
                platform=(
                    Platform.MAC
                    if "American Typewriter Semibold" in fonts
                    else Platform.IOS
                ),
            ),
            fonts,
        )

    elif fonts & WINDOWS_FONTS:
        return (
            BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.WINDOWS),
            fonts,
        )

    elif fonts & LINUX_FONTS:
        return (
            BrowserCheckResult(BrowserCheckVerdict.OK, platform=Platform.LINUX),
            fonts,
        )

    else:
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.SUSPICIOUS, platform=Platform.UNKNOWN
            ),
            fonts,
        )


def check_browser_engine(browserdata: BrowserData) -> BrowserCheckResult:
    if browserdata["engine"].count("|") != 1:
        print("browser engine value is spoofed", browserdata["engine"])
        return BrowserCheckResult(BrowserCheckVerdict.TAMPERED, reason="Engine value")

    tofixed_data, native_data = browserdata["engine"].split("|")

    match tofixed_data:
        case "toFixed() digits argument must be between 0 and 100":
            tofixed_browser = Browser.CHROMIUM  # V8
        case "precision -1 out of range":
            tofixed_browser = Browser.FIREFOX  # SpiderMonkey
        case "toFixed() argument must be between 0 and 100":
            tofixed_browser = Browser.WEBKIT  # JavaScriptCore
        case _:
            tofixed_browser = Browser.UNKNOWN

    match native_data:
        case "function () { [native code] }":
            native_browser = {Browser.CHROMIUM}
        case "function () {\n    [native code]\n}":
            native_browser = {Browser.WEBKIT, Browser.FIREFOX}
        case _:
            native_browser = {Browser.UNKNOWN}

    if tofixed_browser not in native_browser:
        return BrowserCheckResult(
            BrowserCheckVerdict.TAMPERED,
            browser=tofixed_browser,
            reason="Mismatching browser engine",
        )

    return BrowserCheckResult(BrowserCheckVerdict.OK, browser=tofixed_browser)


def check_detections(browserdata: BrowserData) -> BrowserCheckResult:
    try:
        all_detections = list(map(int, browserdata["detections"].split(",")[:-1]))
    except ValueError:
        print("detections contains non-int", browserdata["detections"])
        return BrowserCheckResult(
            BrowserCheckVerdict.TAMPERED, reason="Detections non-int"
        )

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
                results.append(
                    BrowserCheckResult(
                        BrowserCheckVerdict.AUTOMATED,
                        reason=f"Detection: {detection:>04x}",
                    )
                )
            case 2:  # suspicious stuff
                # 0000 pdf disabled
                results.append(
                    BrowserCheckResult(
                        BrowserCheckVerdict.SUSPICIOUS,
                        reason=f"Detection: {detection:>04x}",
                    )
                )
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
                        results.append(
                            BrowserCheckResult(
                                BrowserCheckVerdict.TAMPERED,
                                reason=f"Unknown: {detection:>04x}",
                            )
                        )
            case _:
                print("unknown detection", hex(detection)[2:].zfill(4))
                results.append(
                    BrowserCheckResult(
                        BrowserCheckVerdict.TAMPERED,
                        reason=f"Unknown: {detection:>04x}",
                    )
                )

    browser = Browser.UNKNOWN
    if len(browsers) == 1:
        (browser,) = browsers

    if results:
        return max(results, key=lambda x: x.verdict.value)._replace(browser=browser)

    return BrowserCheckResult(BrowserCheckVerdict.OK, browser=browser)


def check_picasso(browserdata: BrowserData) -> tuple[BrowserCheckResult, int]:
    if len(browserdata["picasso"]) != 24 or not all(
        x in "0123456789abcdef" for x in browserdata["picasso"]
    ):
        print("picasso has incorrect length/values", browserdata["picasso"])
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.TAMPERED, reason="Picasso invalid hex"
            ),
            0,
        )

    picasso = bytes.fromhex(browserdata["picasso"])

    rkey = int.from_bytes(picasso[:4], "big") ^ 0xD0BED0AA
    fp = int.from_bytes(picasso[4:8], "big") ^ rkey
    checksum = int.from_bytes(picasso[8:], "big") ^ 0xFBE2088E

    expected_checksum = crc32(picasso[:8])
    if expected_checksum != checksum:
        print("picasso has incorrect checksum", fp, checksum, expected_checksum)
        return (
            BrowserCheckResult(
                BrowserCheckVerdict.TAMPERED, reason="Picasso invalid checksum"
            ),
            0,
        )

    return BrowserCheckResult(BrowserCheckVerdict.OK), fp
