import json
from redis import asyncio as aioredis
from app.config import settings
import logging

import time

logger = logging.getLogger(__name__)

# In-memory cache fallback for cloud deployments without standalone Redis
IN_MEMORY_CACHE: dict = {}

async def get_redis():
    return await aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1.0)

async def get_cached_scan(domain: str) -> dict | None:
    """Check if domain was scanned within CACHE_TTL_HOURS."""
    # 1. Try Redis
    try:
        redis = await get_redis()
        cached_data = await redis.get(f"scan:{domain}")
        await redis.aclose()
        if cached_data:
            return json.loads(cached_data)
    except Exception:
        pass

    # 2. Fallback to in-memory cache (with TTL expiration check)
    entry = IN_MEMORY_CACHE.get(domain)
    if entry:
        if isinstance(entry, dict) and "expires_at" in entry and "data" in entry:
            if time.time() < entry["expires_at"]:
                return entry["data"]
            else:
                IN_MEMORY_CACHE.pop(domain, None)
        else:
            return entry
    return None

async def set_cached_scan(domain: str, result: dict) -> None:
    """Store scan result with TTL."""
    ttl_hours = getattr(settings, "CACHE_TTL_HOURS", 24)
    ttl_seconds = ttl_hours * 3600

    # Always save to in-memory cache with expiration timestamp
    IN_MEMORY_CACHE[domain] = {
        "data": result,
        "expires_at": time.time() + ttl_seconds
    }

    # Also persist to Redis if reachable
    try:
        redis = await get_redis()
        await redis.setex(f"scan:{domain}", ttl_seconds, json.dumps(result))
        await redis.aclose()
    except Exception:
        pass
