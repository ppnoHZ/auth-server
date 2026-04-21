import json
from typing import Optional, Any
import aioredis
from app.config import settings

class RedisManager:
    def __init__(self, url: str):
        self.url = url
        self.redis: Optional[aioredis.Redis] = None

    async def get_redis(self) -> aioredis.Redis:
        if self.redis is None:
            self.redis = aioredis.from_url(self.url, decode_responses=True)
        return self.redis

    async def close(self):
        if self.redis:
            await self.redis.close()
            self.redis = None

    async def set_json(self, key: str, value: Any, expire: int = None):
        r = await self.get_redis()
        await r.set(key, json.dumps(value), ex=expire)

    async def get_json(self, key: str) -> Optional[Any]:
        r = await self.get_redis()
        val = await r.get(key)
        if val:
            return json.loads(val)
        return None

    async def delete(self, key: str):
        r = await self.get_redis()
        await r.delete(key)

redis_manager = RedisManager(settings.REDIS_URL)

async def get_redis_client():
    return await redis_manager.get_redis()
