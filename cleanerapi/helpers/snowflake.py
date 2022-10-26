import random
from datetime import datetime, timezone

DISCORD_EPOCH = 1_420_070_400_000


def generate_snowflake() -> int:
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    timestamp = int(now.timestamp() * 1000) - DISCORD_EPOCH
    return timestamp << 22 | random.randint(0, 1 << 22)
