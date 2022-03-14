from fastapi import APIRouter, Request

from ..models import RadarInfo


router = APIRouter()


@router.get("/radar", response_model=RadarInfo)
async def get_radar():
    # TODO
    return {
        "rules": {
            "phishing.content": {"previous": 5, "now": 5},
            "phishing.domain.heuristic": {"previous": 4, "now": 0},
            "phishing.embed": {"previous": 0, "now": 0},
            "self_bot.embed": {"previous": 0, "now": 0},
            "mass_ping.hidden": {"previous": 0, "now": 0},
            "mass_ping.roles": {"previous": 0, "now": 0},
            "mass_ping.users.many": {"previous": 0, "now": 0},
            "mass_ping.users.few": {"previous": 0, "now": 0},
            "mass_ping.broad": {"previous": 5, "now": 4},
            "advertisement.discord_invite": {"previous": 7, "now": 3},
            "emoji.mass": {"previous": 0, "now": 0},
            "link.checker": {"previous": 0, "now": 0},
        },
        "traffic": {"traffic.similar": {"previous": 4, "now": 3}},
        "last_data": "2022-03-08T18:58:43",
        "stats_phishing": {"previous": 14, "now": 9},
        "stats_antispam": {"previous": 4, "now": 3},
        "stats_advertisement": {"previous": 7, "now": 3},
        "stats_other": {"previous": 0, "now": 0},
        "challenges_ban": {"previous": 10, "now": 6},
        "challenges_auth": {"previous": 0, "now": 0},
        "challenges_captcha": {"previous": 0, "now": 0},
        "challenges_timeout": {"previous": 0, "now": 0},
    }
