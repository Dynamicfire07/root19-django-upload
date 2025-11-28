from .streaks import compute_streak


def streak_context(request):
    """Inject streak counts for logged-in users."""
    user_id = request.session.get("user_id")
    if not user_id:
        return {}
    streak = compute_streak(user_id)
    return {
        "streak_current": streak.get("current", 0),
        "streak_best": streak.get("best", 0),
    }
