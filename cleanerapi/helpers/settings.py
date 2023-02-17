import typing

import msgpack  # type: ignore
from coredis import Redis

default_config = {
    "rules_phishing_content": 2,
    "rules_phishing_content_channels": [],
    "rules_phishing_domain_blacklisted": 2,
    "rules_phishing_domain_blacklisted_channels": [],
    "rules_phishing_domain_heuristic": 2,
    "rules_phishing_domain_heuristic_channels": [],
    "rules_phishing_embed": 2,
    "rules_phishing_embed_channels": [],
    "rules_selfbot_embed": 2,
    "rules_selfbot_embed_channels": [],
    "rules_ping_hidden": 1,
    "rules_ping_hidden_channels": [],
    "rules_ping_roles": 2,
    "rules_ping_roles_channels": [],
    "rules_ping_users_many": 2,
    "rules_ping_users_many_channels": [],
    "rules_ping_users_few": 1,
    "rules_ping_users_few_channels": [],
    "rules_ping_broad": 1,
    "rules_ping_broad_channels": [],
    "rules_advertisement_discord_invite": 1,
    "rules_advertisement_discord_invite_channels": [],
    "rules_advertisement_discord_unsafeinvite": 2,
    "rules_advertisement_discord_unsafeinvite_channels": [],
    "rules_emoji_mass": 0,
    "rules_emoji_mass_channels": [],
    "antispam_similar": True,
    "antispam_similar_channels": [],
    "antispam_exact": True,
    "antispam_exact_channels": [],
    "antispam_token": True,
    "antispam_token_channels": [],
    "antispam_sticker": True,
    "antispam_sticker_channels": [],
    "antispam_attachment": True,
    "antispam_attachment_channels": [],
    "antispam_anomaly": False,
    "antispam_anomaly_channels": [],
    "antispam_anomaly_score": 30,
    "antiraid_enabled": False,
    "antiraid_limit": "5/30",
    "antiraid_mode": 0,  # all/1day/3days/week
    "general_modroles": [],
    "slowmode_enabled": True,
    "slowmode_exceptions": [],
    "punishments_timeout_enabled": True,
    "punishments_verification_enabled": True,
    "verification_enabled": False,
    "verification_role": "0",
    "verification_take_role": False,
    "verification_age": 7776000,  # 3 months
    "super_verification_enabled": False,
    "super_verification_captcha": False,
    "super_verification_role": "0",
    "verification_timelimit_enabled": False,
    "verification_timelimit": 480,
    "logging_enabled": False,
    "logging_channel": "0",
    "logging_option_join": False,
    "logging_option_join_risky": False,
    "logging_option_leave": False,
    "name_dehoisting_enabled": True,
    "name_discord_enabled": True,
    "name_advanced_enabled": False,
    "name_advanced_words": [],
    "joinguard_enabled": False,
    "joinguard_captcha": False,
    "report_enabled": False,
    "report_channel": "0",
    "branding_splash_enabled": False,
    "branding_embed_enabled": False,
    "branding_embed_title": "",
    "branding_embed_description": "",
    "access_permissions": 2,  # off/admin/admin+manager
    "access_members": [],
    "access_mfa": False,
    "antinuke_bots": 0,  # all/verified only/no
    "antinuke_webhooks": False,
    "auth_enabled": False,
    "auth_roles": {},
    "bansync_subscribed": [],
    "linkfilter_enabled": False,
    "linkfilter_channel": "0",
    "linkfilter_blockunknown": False,
    "linkfilter_linkpreview": False,
    "filterrules_enabled": False,
}

default_entitlements = {
    "plan": 0,
    "suspended": "",
    "partnered": False,
    "access": 0,
    "antiraid": 0,  # unused
    "antispam": 0,  # unused
    "automod": 0,  # unused
    "branding_splash": 1,
    "branding_embed": 1,
    "branding_vanity": 1,
    "branding_vanity_url": "",
    "contact_standard": 1,
    "contact_email": 1,
    "joinguard": 1,
    "logging": 0,  # unused
    "logging_downloads": 1,
    "logging_retention": 3,
    "slowmode": 0,  # unused
    "statistics": 0,
    "report": 1,
    "name_advanced": 1,
    "verification": 0,  # unused
    "super_verification": 0,
    "verification_timelimit": 0,
    "bansync_subscription_limit": 10,
    "auth": 1,
    "linkfilter": 0,
    "filterrules": 1,
}


def validate_int_range(min: int, max: int) -> typing.Callable[[int | typing.Any], bool]:
    return lambda x: isinstance(x, int) and max >= x >= min


def validate_snowflake(x: str | typing.Any) -> bool:
    return isinstance(x, str) and x.isdigit() and (20 >= len(x) >= 16 or x == "0")


def validate_snowflakes(x: list[str] | typing.Any) -> bool:
    return isinstance(x, list) and all(map(validate_snowflake, x)) and 250 >= len(x)


def validate_boolean(x: bool | typing.Any) -> bool:
    return x in (True, False)


_cfg_fw_mode = validate_int_range(0, 2)
config_validators: dict[str, typing.Callable[..., bool]] = {
    "rules_phishing_content": _cfg_fw_mode,
    "rules_phishing_content_channels": validate_snowflakes,
    "rules_phishing_domain_blacklisted": _cfg_fw_mode,
    "rules_phishing_domain_blacklisted_channels": validate_snowflakes,
    "rules_phishing_domain_heuristic": _cfg_fw_mode,
    "rules_phishing_domain_heuristic_channels": validate_snowflakes,
    "rules_phishing_embed": _cfg_fw_mode,
    "rules_phishing_embed_channels": validate_snowflakes,
    "rules_selfbot_embed": _cfg_fw_mode,
    "rules_selfbot_embed_channels": validate_snowflakes,
    "rules_ping_hidden": _cfg_fw_mode,
    "rules_ping_hidden_channels": validate_snowflakes,
    "rules_ping_roles": _cfg_fw_mode,
    "rules_ping_roles_channels": validate_snowflakes,
    "rules_ping_users_many": _cfg_fw_mode,
    "rules_ping_users_many_channels": validate_snowflakes,
    "rules_ping_users_few": _cfg_fw_mode,
    "rules_ping_users_few_channels": validate_snowflakes,
    "rules_ping_broad": _cfg_fw_mode,
    "rules_ping_broad_channels": validate_snowflakes,
    "rules_advertisement_discord_invite": _cfg_fw_mode,
    "rules_advertisement_discord_invite_channels": validate_snowflakes,
    "rules_advertisement_discord_unsafeinvite": _cfg_fw_mode,
    "rules_advertisement_discord_unsafeinvite_channels": validate_snowflakes,
    "rules_emoji_mass": _cfg_fw_mode,
    "rules_emoji_mass_channels": validate_snowflakes,
    "antispam_similar": validate_boolean,
    "antispam_similar_channels": validate_snowflakes,
    "antispam_exact": validate_boolean,
    "antispam_exact_channels": validate_snowflakes,
    "antispam_token": validate_boolean,
    "antispam_token_channels": validate_snowflakes,
    "antispam_sticker": validate_boolean,
    "antispam_sticker_channels": validate_snowflakes,
    "antispam_attachment": validate_boolean,
    "antispam_attachment_channels": validate_snowflakes,
    "antispam_anomaly": validate_boolean,
    "antispam_anomaly_channels": validate_snowflakes,
    "antispam_anomaly_score": lambda x: isinstance(x, int) and 100 >= x > 0,
    "antiraid_enabled": validate_boolean,
    "antiraid_limit": (
        lambda x: isinstance(x, str)
        and x.count("/") == 1
        and all(map(lambda y: y and y.isdigit() and len(y) < 4, x.split("/")))
    ),
    "antiraid_mode": (
        lambda x: isinstance(x, int) and 3 >= x >= 0  # all/1day/3days/week
    ),
    "general_modroles": validate_snowflakes,
    "slowmode_enabled": validate_boolean,
    "slowmode_exceptions": validate_snowflakes,
    "punishments_timeout_enabled": validate_boolean,
    "punishments_verification_enabled": validate_boolean,
    "verification_enabled": validate_boolean,
    "verification_role": validate_snowflake,
    "verification_take_role": validate_boolean,
    "verification_age": lambda x: isinstance(x, int) and (1 << 32) >= x >= 0,
    "super_verification_enabled": validate_boolean,
    "super_verification_captcha": validate_boolean,
    "super_verification_role": validate_snowflake,
    "verification_timelimit_enabled": validate_boolean,
    "verification_timelimit": validate_int_range(60, 60 * 60 * 24 * 7),
    "logging_enabled": validate_boolean,
    "logging_channel": validate_snowflake,
    "logging_option_join": validate_boolean,
    "logging_option_join_risky": validate_boolean,
    "logging_option_leave": validate_boolean,
    "name_dehoisting_enabled": validate_boolean,
    "name_discord_enabled": validate_boolean,
    "name_advanced_enabled": validate_boolean,
    "name_advanced_words": (
        lambda x: isinstance(x, list)
        and all(map(lambda y: isinstance(y, str) and 32 >= len(y) > 0, x))
    ),
    "joinguard_enabled": validate_boolean,
    "joinguard_captcha": validate_boolean,
    "report_enabled": validate_boolean,
    "report_channel": validate_snowflake,
    "branding_splash_enabled": validate_boolean,
    "branding_embed_enabled": validate_boolean,
    "branding_embed_title": lambda x: isinstance(x, str) and 200 > len(x),
    "branding_embed_description": lambda x: isinstance(x, str) and 2000 > len(x),
    "access_permissions": (
        lambda x: isinstance(x, int) and 2 >= x >= 0  # off/admin/admin+manager
    ),
    "access_members": validate_snowflakes,
    "access_mfa": validate_boolean,
    "antinuke_bots": (
        lambda x: isinstance(x, int) and 2 >= x >= 0  # all/verified only/no
    ),
    "antinuke_webhooks": validate_boolean,
    "auth_enabled": validate_boolean,
    "auth_roles": lambda x: (
        isinstance(x, dict)
        and validate_snowflakes(list(x.keys()))
        and all(map(validate_snowflakes, x.values()))
    ),
    "bansync_subscribed": validate_snowflakes,
    "linkfilter_enabled": validate_boolean,
    "linkfilter_channel": validate_snowflake,
    "linkfilter_blockunknown": validate_boolean,
    "linkfilter_linkpreview": validate_boolean,
    "filterrules_enabled": validate_boolean,
}


async def get_config(database: Redis[bytes], guild_id: int) -> dict[str, typing.Any]:
    raw_config = await database.hgetall(f"guild:{guild_id}:config")
    return {**default_config, **decode_settings(raw_config)}


async def get_config_field(
    database: Redis[bytes], guild_id: int | str, field: str
) -> typing.Any:
    value = await database.hget(f"guild:{guild_id}:config", field)
    return default_config[field] if value is None else msgpack.unpackb(value)


async def set_config(
    database: Redis[bytes], guild_id: int | str, config: dict[str, typing.Any]
) -> None:
    raw_config = typing.cast(
        dict[str | bytes, str | bytes | int | float],
        {k: msgpack.packb(v) for k, v in config.items()},
    )
    await database.hset(f"guild:{guild_id}:config", raw_config)


async def get_entitlements(
    database: Redis[bytes], guild_id: int | str
) -> dict[str, typing.Any]:
    raw_entitlements = await database.hgetall(f"guild:{guild_id}:entitlements")
    return {
        **default_entitlements,
        **decode_settings(raw_entitlements),
    }


async def get_entitlement_field(
    database: Redis[bytes], guild_id: int | str, field: str
) -> typing.Any:
    value = await database.hget(f"guild:{guild_id}:entitlements", field)
    return default_entitlements[field] if value is None else msgpack.unpackb(value)


async def set_entitlements(
    database: Redis[bytes], guild_id: int | str, entitlements: dict[str, typing.Any]
) -> None:
    raw_entitlements = typing.cast(
        dict[str | bytes, str | bytes | int | float],
        {k: msgpack.packb(v) for k, v in entitlements.items()},
    )
    await database.hset(f"guild:{guild_id}:entitlements", raw_entitlements)


def decode_settings(dictionary: dict[bytes, bytes]) -> dict[str, str | int | bool]:
    return {key.decode(): msgpack.unpackb(value) for key, value in dictionary.items()}
