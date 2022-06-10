import typing


class TStat(typing.TypedDict):
    total: int
    previous: int
    now: int


class TRadarInfo(typing.TypedDict):
    rules: dict[str, TStat]
    traffic: dict[str, TStat]
    categories: dict[str, TStat]
    challenges: dict[str, TStat]
    TStats: dict[str, int]


class TStatisticsInfo(typing.TypedDict):
    rules: dict[str, TStat]
    traffic: dict[str, TStat]
    categories: dict[str, TStat]
    challenges: dict[str, TStat]


class TPartialGuildInfo(typing.TypedDict, total=False):
    id: str
    name: str
    icon: str | None
    access_type: int


class TGuildInfo(TPartialGuildInfo):
    is_added: bool
    is_suspended: bool


class TUserInfo(typing.TypedDict):
    id: str
    name: str
    discriminator: str
    avatar: str | None


class TGIRole(typing.TypedDict):
    name: str
    id: str
    can_control: bool
    is_managed: bool


class TGIChannel(typing.TypedDict):
    name: str
    id: str
    permissions: dict[str, bool]


class TGIMyself(typing.TypedDict):
    permissions: dict[str, bool]


class TGIGuild(typing.TypedDict):
    id: str
    name: str
    roles: list[TGIRole] | None
    channels: list[TGIChannel] | None
    myself: TGIMyself | None


class TGIUser(TUserInfo):
    is_dev: bool | None


class TDetailedGuildInfo(typing.TypedDict, total=False):
    guild: TGIGuild | None
    entitlements: typing.Any | None
    config: typing.Any | None
    user: TGIUser


class TChallengerResponse(typing.TypedDict):
    user: TUserInfo
    is_valid: bool
    captcha_required: bool
    splash: str | None


class TChallengerResponseWithJoinScope(TChallengerResponse):
    has_join_scope: bool


class TChallengerRequest(typing.TypedDict):
    token: str | None


class TVanityResponse(typing.TypedDict):
    guild: str
    splash: bool


class TChannelId(typing.TypedDict):
    channel_id: int


class TRemoteAuth(typing.TypedDict):
    code: str


class TRemoteAuthResponse(typing.TypedDict):
    token: str


class TOAuthCallbackResponse(typing.TypedDict, total=False):
    redirect: str
    token: str | None
    guild: str | None


class TGuildSnapshot(typing.TypedDict):
    id: str
    timestamp: str
    channels: int
    roles: int


class TAuthObject(typing.TypedDict):
    token: str
    scopes: list[str]
