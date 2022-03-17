import typing

from pydantic import BaseModel


class RadarStat(BaseModel):
    previous: int
    now: int


class RadarInfo(BaseModel):
    rules: typing.Dict[str, RadarStat]
    traffic: typing.Dict[str, RadarStat]
    categories: typing.Dict[str, RadarStat]
    challenges: typing.Dict[str, RadarStat]
    stats: typing.Dict[str, int]


class GuildInfo(BaseModel):
    id: str
    name: str
    icon: typing.Optional[str]
    is_owner: bool
    is_admin: bool
    is_added: bool
    is_suspended: bool


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
    roles: typing.Optional[typing.List[GIRole]]
    channels: typing.Optional[typing.List[GIChannel]]
    myself: typing.Optional[GIMyself]


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


class Challenge(BaseModel):
    flow: str
    captcha: typing.Optional[str]


class ChannelId(BaseModel):
    channel_id: int


class RemoteAuth(BaseModel):
    code: str
