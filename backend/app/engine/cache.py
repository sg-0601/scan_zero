import json
from redis import asyncio as aioredis
from app.config import settings
import logging

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

    # 2. Fallback to in-memory cache
    return IN_MEMORY_CACHE.get(domain)

async def set_cached_scan(domain: str, result: dict) -> None:
    """Store scan result with TTL."""
    # Always save to in-memory cache
    IN_MEMORY_CACHE[domain] = result

    # Also persist to Redis if reachable
    try:
        redis = await get_redis()
        ttl_seconds = settings.CACHE_TTL_HOURS * 3600
        await redis.setex(f"scan:{domain}", ttl_seconds, json.dumps(result))
        await redis.aclose()
    except Exception:
        pass
