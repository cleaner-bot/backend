from sanic import Blueprint

from . import bansync, chl, guild, oauth2, statistics, user

api = Blueprint.group(
    bansync.bp,
    user.user_bp,
    guild.guild_bp,
    oauth2.bp,
    chl.bp,
    statistics.bp,
)
