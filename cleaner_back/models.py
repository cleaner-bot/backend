from datetime import datetime
from lib2to3.pytree import Base
import typing

from pydantic import BaseModel


class RadarStat(BaseModel):
    previous: int
    now: int


class RadarInfo(BaseModel):
    stats_phishing: RadarStat
    stats_antispam: RadarStat
    stats_advertisement: RadarStat
    stats_other: RadarStat
    rules: typing.Dict[str, RadarStat]
    traffic: typing.Dict[str, RadarStat]
    challenges_ban: RadarStat
    challenges_auth: RadarStat
    challenges_captcha: RadarStat
    challenges_timeout: RadarStat

    last_data: str


class GuildInfo(BaseModel):
    id: str
    name: str
    icon: typing.Optional[str]
    is_owner: bool
    is_added: bool
    is_admin: bool


class UserInfo(BaseModel):
    id: str
    name: str
    avatar: typing.Optional[str]


class GIRole(BaseModel):
    name: str
    id: str
    can_control: bool
    is_managed: bool


class GIChannel(BaseModel):
    name: str
    id: str
    permissions: typing.Dict[str, bool]


class GIMyself(BaseModel):
    permissions: typing.Dict[str, bool]


class GIGuild(BaseModel):
    id: str
    name: str
    roles: typing.List[GIRole]
    channels: typing.List[GIChannel]
    me: GIMyself


class GIUser(BaseModel):
    id: str
    name: str
    avatar: str
    is_dev: typing.Optional[bool]


class DetailedGuildInfo(BaseModel):
    guild: typing.Optional[GIGuild]
    entitlements: typing.Optional[typing.Dict[str, typing.Union[int, bool]]]
    config: typing.Optional[typing.Dict[str, str]]
    user: GIUser


class DownloadInfo(BaseModel):
    year: int
    month: int
    expired: bool
