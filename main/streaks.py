from datetime import datetime, timezone, timedelta

from django.core.cache import cache

from .db import query_all

STREAK_THRESHOLD = 5
_CACHE_KEY = "streak:{user_id}"
# Cache streaks briefly to avoid repeating the heavy aggregate on every request.
STREAK_CACHE_TTL = 300


def _cache_key(user_id: str) -> str:
    return _CACHE_KEY.format(user_id=user_id)


def compute_streak(user_id: str) -> dict:
    """Return current and best streak (days with at least STREAK_THRESHOLD solves)."""
    if not user_id:
        return {"current": 0, "best": 0}

    cached = cache.get(_cache_key(user_id))
    if cached is not None:
        return cached

    rows = query_all(
        """
        SELECT DATE(COALESCE(time_started, NOW())) AS day,
               COUNT(*) FILTER (WHERE solved = TRUE) AS solved_count
        FROM user_activity
        WHERE user_id = %s AND solved = TRUE
        GROUP BY day
        ORDER BY day DESC
        """,
        (user_id,),
    )

    day_map = {
        row.get("day"): row.get("solved_count", 0) or 0
        for row in rows
        if row.get("day") is not None
    }

    today = datetime.now(timezone.utc).date()
    current = 0
    cursor = today
    while day_map.get(cursor, 0) >= STREAK_THRESHOLD:
        current += 1
        cursor = cursor - timedelta(days=1)

    best = 0
    run = 0
    prev_day = None
    for day in sorted(day_map.keys()):
        if day_map.get(day, 0) < STREAK_THRESHOLD:
            run = 0
            prev_day = None
            continue
        if prev_day and (day - prev_day).days == 1:
            run += 1
        else:
            run = 1
        prev_day = day
        best = max(best, run)

    result = {"current": current, "best": best}
    cache.set(_cache_key(user_id), result, STREAK_CACHE_TTL)
    return result


def invalidate_streak_cache(user_id: str) -> None:
    """Clear cached streaks when new activity is recorded."""
    if not user_id:
        return
    cache.delete(_cache_key(user_id))
