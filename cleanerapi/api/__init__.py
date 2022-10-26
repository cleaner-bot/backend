from sanic import Blueprint

from . import guild, oauth2, user, bansync, chl, statistics

api = Blueprint.group(
    bansync.bp,
    user.user_bp,
    guild.guild_bp,
    oauth2.bp,
    chl.bp,
    statistics.bp,
)
