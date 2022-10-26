import asyncio
from collections import defaultdict

named_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
