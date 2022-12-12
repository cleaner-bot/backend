from sanic import Blueprint

from . import chl, guild, oauth2, statistics, user

api = Blueprint.group(
    user.user_bp,
    guild.guild_bp,
    oauth2.bp,
    chl.bp,
    statistics.bp,
)
