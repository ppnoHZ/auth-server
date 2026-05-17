from fastapi import HTTPException, status

from app.redis import redis_manager


def build_rate_limit_key(prefix: str, *parts: str) -> str:
    normalized_parts = []
    for part in parts:
        clean = (part or "unknown").strip().lower()
        normalized_parts.append(clean[:128])
    return "rate_limit:" + prefix + ":" + ":".join(normalized_parts)


async def get_retry_after(key: str, max_attempts: int) -> int:
    try:
        attempts = await redis_manager.get_int(key)
    except Exception:
        return 0
    if attempts is None or attempts < max_attempts:
        return 0

    try:
        ttl = await redis_manager.ttl(key)
    except Exception:
        return 0
    return max(ttl, 1)


async def enforce_rate_limit(key: str, max_attempts: int, detail: str) -> None:
    retry_after = await get_retry_after(key, max_attempts)
    if retry_after > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(retry_after)},
        )


async def record_failure(key: str, window_seconds: int) -> int:
    try:
        return await redis_manager.increment(key, expire=window_seconds)
    except Exception:
        return 0


async def clear_failures(key: str) -> None:
    try:
        await redis_manager.delete(key)
    except Exception:
        return None