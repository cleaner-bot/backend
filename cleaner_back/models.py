from pydantic import BaseModel

from cleaner_conf.guild import GuildConfig, GuildEntitlements


class Stat(BaseModel):
    total: int
    previous: int
    now: int


class RadarInfo(BaseModel):
    rules: dict[str, Stat]
    traffic: dict[str, Stat]
    categories: dict[str, Stat]
    challenges: dict[str, Stat]
    stats: dict[str, int]


class StatisticsInfo(BaseModel):
    rules: dict[str, Stat]
    traffic: dict[str, Stat]
    categories: dict[str, Stat]
    challenges: dict[str, Stat]


class GuildInfo(BaseModel):
    id: str
    name: str
    icon: str | None
    is_owner: bool
    is_admin: bool
    is_added: bool
    is_suspended: bool


class UserInfo(BaseModel):
    id: str
    name: str
    discriminator: str
    avatar: str | None


class GIRole(BaseModel):
    name: str
    id: str
    can_control: bool
    is_managed: bool


class GIChannel(BaseModel):
    name: str
    id: str
    permissions: dict[str, bool]


class GIMyself(BaseModel):
    permissions: dict[str, bool]


class GIGuild(BaseModel):
    id: str
    name: str
    roles: list[GIRole] | None
    channels: list[GIChannel] | None
    myself: GIMyself | None


class GIUser(BaseModel):
    id: str
    name: str
    avatar: str | None
    is_dev: bool | None


class DetailedGuildInfo(BaseModel):
    guild: GIGuild | None
    entitlements: GuildEntitlements | None
    config: GuildConfig | None
    user: GIUser


class DownloadInfo(BaseModel):
    year: int
    month: int
    expired: bool


class ChallengerResponse(BaseModel):
    user: UserInfo
    is_valid: bool
    captcha_required: bool
    splash: str | None


class ChallengerRequest(BaseModel):
    token: str | None


class ChannelId(BaseModel):
    channel_id: int


class RemoteAuth(BaseModel):
    code: str
