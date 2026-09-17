import json
from redis import asyncio as aioredis
from app.config import settings
import logging

logger = logging.getLogger(__name__)

async def get_redis():
    return await aioredis.from_url(settings.REDIS_URL, decode_responses=True)

async def get_cached_scan(domain: str) -> dict | None:
    """Check if domain was scanned within CACHE_TTL_HOURS."""
    try:
        redis = await get_redis()
        cached_data = await redis.get(f"scan:{domain}")
        await redis.aclose()
        
        if cached_data:
            return json.loads(cached_data)
        return None
    except Exception as e:
        logger.error(f"Redis cache error: {e}")
        return None

async def set_cached_scan(domain: str, result: dict) -> None:
    """Store scan result with TTL."""
    try:
        redis = await get_redis()
        ttl_seconds = settings.CACHE_TTL_HOURS * 3600
        await redis.setex(f"scan:{domain}", ttl_seconds, json.dumps(result))
        await redis.aclose()
    except Exception as e:
        logger.error(f"Redis cache error: {e}")
