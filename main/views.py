from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.admin.views.decorators import staff_member_required
from django.core.cache import cache
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from django.utils.crypto import get_random_string
import random
import secrets
import string
import json
import typing as _t

SESSION_LABELS = {
    "620": "Chemistry",
    "625": "Physics",
    "610": "Biology",
}


def label_session(code: str) -> str:
    """Human-friendly label for session code."""
    if not code:
        return ""
    normalized = code.lstrip("0") or code
    return SESSION_LABELS.get(normalized, SESSION_LABELS.get(code, code))


def display_session_code(code: str) -> str:
    """Display session code with leading zero padding when numeric."""
    if not code or not code.isdigit():
        return code or ""
    return code.zfill(4)


def generate_temp_password(length: int = 12) -> str:
    """Generate a readable temporary password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

from .db import (
    query_one,
    query_all,
    execute,
    get_next_user_id,
    get_or_create_activity,
)
from .streaks import compute_streak, invalidate_streak_cache
from .models import BugReport

CHAMPION_CACHE_KEY = "weekly_champion"
CHAMPION_CACHE_TTL = 1800  # 30 minutes
TOTAL_QUESTIONS_CACHE_KEY = "home_total_questions"
TOTAL_QUESTIONS_TTL = 300  # 5 minutes
SESSION_OPTIONS_CACHE_KEY = "session_options"
SESSION_OPTIONS_TTL = 600  # 10 minutes
SUBTOPIC_CACHE_TTL = 600

_study_progress_ready = False
_password_request_ready = False
_CACHE_MISS = object()

# -------------------------
# AUTHENTICATION
# -------------------------

def register(request):
    """Handle user registration."""
    if request.method == 'POST':
        ensure_champion_access_field()
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirmation_password = request.POST['confirmation_password']
        role = request.POST['role']
        school = request.POST['school']

        # Password check
        if password != confirmation_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        # User already exists
        if query_one("SELECT 1 FROM users WHERE email = %s", (email,)):
            messages.error(request, "Email is already registered.")
            return redirect('register')

        # Hash password
        hashed_password = make_password(password)

        # Insert user
        execute(
            """
            INSERT INTO users (user_id, name, email, password, role, school, champion_theme_access)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                get_next_user_id(),
                name,
                email,
                hashed_password,
                role,
                school,
                False,
            ),
        )
        messages.success(request, "Registration successful! Please log in.")
        return redirect('login')

    return render(request, 'register.html')


def login_view(request):
    """Handle login using the users table."""
    if request.method == 'POST':
        ensure_champion_access_field()
        email = request.POST['email']
        password = request.POST['password']
        remember_me = request.POST.get('remember_me') == 'on'

        user = query_one("SELECT * FROM users WHERE email = %s", (email,))
        if user and check_password(password, user.get('password', '')):
            # ✅ Store both user_id and user_name in session
            request.session['user_id'] = user['user_id']
            request.session['user_name'] = user['name']
            if remember_me:
                # 30-day rolling session
                request.session.set_expiry(60 * 60 * 24 * 30)
            else:
                # Expire when browser closes
                request.session.set_expiry(0)
            request.session['champion_access'] = bool(user.get('champion_theme_access'))
            if user.get('champion_theme_access'):
                request.session['champion_name'] = user.get('name') or user.get('email')

            messages.success(request, f"Welcome back, {user['name']}!")
            return redirect('home')

        messages.error(request, "Invalid email or password.")
        return redirect('login')

    return render(request, 'login.html')


def logout_view(request):
    """Log out the user."""
    if 'user_id' not in request.session:
        messages.error(request, "You are not logged in.")
        return redirect('login')

    try:
        request.session.flush()  # ✅ clears user_id and user_name
        messages.success(request, "You have been logged out.")
    except Exception as e:
        messages.error(request, f"An error occurred during logout: {str(e)}")

    return redirect('login')


def change_password(request):
    """Allow a logged-in user to change their password by confirming the current one."""
    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Please log in to change your password.")
        return redirect("login")

    user = query_one("SELECT * FROM users WHERE user_id = %s", (user_id,))
    if not user:
        messages.error(request, "Account not found.")
        return redirect("login")

    if request.method == "POST":
        current_password = request.POST.get("current_password", "")
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")

        if not current_password or not new_password or not confirm_password:
            messages.error(request, "Please fill out all fields.")
            return redirect("change_password")

        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect("change_password")

        if not check_password(current_password, user.get("password", "")):
            messages.error(request, "Current password is incorrect.")
            return redirect("change_password")

        hashed = make_password(new_password)
        execute(
            "UPDATE users SET password = %s WHERE user_id = %s",
            (hashed, user_id),
        )
        messages.success(request, "Password updated successfully.")
        return redirect("change_password")

    return render(request, "change_password.html")


def password_reset_request(request):
    """Let users raise a password reset request by email (manual handling)."""
    ensure_password_request_table()

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        reason = request.POST.get("reason", "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("password_reset_request")

        execute(
            "INSERT INTO password_reset_requests (email, reason) VALUES (%s, %s)",
            (email, reason or None),
        )
        messages.success(request, "Request received. We'll review and help you reset your password.")
        return redirect("password_reset_request")

    return render(request, "password_reset_request.html")

# -------------------------
# MAIN PAGES
# -------------------------

def home(request):
    """Render the home page with the question count."""
    champion = update_weekly_champion()
    total_questions = get_total_questions_count()

    # Refresh session flags based on champion rotation
    session_user_id = request.session.get("user_id")
    if session_user_id:
        if champion and session_user_id == champion.get("user_id"):
            request.session["champion_access"] = True
            request.session["champion_name"] = champion.get("name")
        else:
            request.session["champion_access"] = False
            request.session.pop("champion_name", None)

    return render(request, 'home.html', {'total_questions': total_questions})


def ensure_study_progress_table():
    """Create study_progress table if it does not exist (idempotent)."""
    global _study_progress_ready
    if _study_progress_ready:
        return
    execute(
        """
        CREATE TABLE IF NOT EXISTS study_progress (
            id SERIAL PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            session_code VARCHAR(100) NOT NULL,
            subtopic VARCHAR(255) NOT NULL,
            completed BOOLEAN DEFAULT FALSE,
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, session_code, subtopic)
        );
        """
    )
    _study_progress_ready = True


def ensure_password_request_table():
    """Create password_reset_requests table if missing."""
    global _password_request_ready
    if _password_request_ready:
        return
    execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            reason TEXT,
            status VARCHAR(20) DEFAULT 'open',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            handled_at TIMESTAMPTZ
        );
        """
    )
    # Backfill missing columns for existing deployments.
    execute(
        "ALTER TABLE password_reset_requests ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'open';"
    )
    execute(
        "ALTER TABLE password_reset_requests ADD COLUMN IF NOT EXISTS handled_at TIMESTAMPTZ;"
    )
    _password_request_ready = True

def ensure_champion_access_field():
    """Ensure champion_theme_access exists on users."""
    execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS champion_theme_access BOOLEAN DEFAULT FALSE;"
    )

# -------------------------
# DUELS
# -------------------------


def ensure_duel_tables():
    """Create duels table and indexes if missing (idempotent)."""
    execute(
        """
        CREATE TABLE IF NOT EXISTS duels (
            id SERIAL PRIMARY KEY,
            code VARCHAR(12) UNIQUE NOT NULL,
            creator_id VARCHAR(255) NOT NULL,
            opponent_id VARCHAR(255),
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            syllabus_code VARCHAR(100),
            question_ids JSONB NOT NULL,
            time_limit_seconds INTEGER NOT NULL DEFAULT 180,
            start_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ,
            pending_expires_at TIMESTAMPTZ,
            winner VARCHAR(20),
            creator_submitted BOOLEAN DEFAULT FALSE,
            opponent_submitted BOOLEAN DEFAULT FALSE,
            creator_answers JSONB,
            opponent_answers JSONB,
            creator_score JSONB,
            opponent_score JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        """
    )
    execute("CREATE INDEX IF NOT EXISTS idx_duels_code ON duels (code)")
    execute("CREATE INDEX IF NOT EXISTS idx_duels_status ON duels (status)")
    execute("CREATE INDEX IF NOT EXISTS idx_duels_expires ON duels (expires_at)")


def _parse_json_field(val, fallback):
    if val is None:
        return fallback
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return fallback


def _generate_duel_code() -> str:
    return get_random_string(6, allowed_chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789")


def _pick_question_ids(limit: int, syllabus_code: _t.Optional[str] = None) -> _t.List[str]:
    if syllabus_code:
        rows = query_all(
            "SELECT question_id FROM questions WHERE session_code = %s",
            (syllabus_code,),
        )
    else:
        rows = query_all("SELECT question_id FROM questions")
    pool = [r["question_id"] for r in rows]
    if not pool:
        return []
    if len(pool) <= limit:
        random.shuffle(pool)
        return pool
    return random.sample(pool, limit)


def _serialize_duel(row: dict) -> dict:
    question_ids = _parse_json_field(row.get("question_ids"), [])
    return {
        "id": row.get("id"),
        "code": row.get("code"),
        "creator_id": row.get("creator_id"),
        "opponent_id": row.get("opponent_id"),
        "status": row.get("status"),
        "syllabus_code": row.get("syllabus_code"),
        "question_ids": question_ids,
        "time_limit_seconds": row.get("time_limit_seconds"),
        "start_at": row.get("start_at").isoformat() if row.get("start_at") else None,
        "expires_at": row.get("expires_at").isoformat() if row.get("expires_at") else None,
        "pending_expires_at": row.get("pending_expires_at").isoformat() if row.get("pending_expires_at") else None,
        "winner": row.get("winner"),
        "creator_submitted": bool(row.get("creator_submitted")),
        "opponent_submitted": bool(row.get("opponent_submitted")),
        "creator_score": _parse_json_field(row.get("creator_score"), {}),
        "opponent_score": _parse_json_field(row.get("opponent_score"), {}),
    }


def _compute_winner(duel: dict, expired: bool = False) -> str:
    creator_score = _parse_json_field(duel.get("creator_score"), {}) or {}
    opponent_score = _parse_json_field(duel.get("opponent_score"), {}) or {}
    c_correct = int(creator_score.get("correct", 0) or 0)
    o_correct = int(opponent_score.get("correct", 0) or 0)
    c_time = float(creator_score.get("time_taken_seconds", 0) or 0)
    o_time = float(opponent_score.get("time_taken_seconds", 0) or 0)

    if c_correct > o_correct:
        return "creator"
    if o_correct > c_correct:
        return "opponent"
    if c_correct == 0 and o_correct == 0 and expired:
        # No valid submissions; treat as no winner.
        return "none"
    if c_correct == o_correct:
        if c_time and o_time:
            if c_time < o_time:
                return "creator"
            if o_time < c_time:
                return "opponent"
        return "draw"
    return "draw"


def _auto_finalize_if_needed(duel: dict) -> dict:
    """Expire pending/active duels when timers elapse."""
    now = datetime.now(timezone.utc)
    status = duel.get("status")
    duel_id = duel.get("id")

    # Pending expiry
    pending_expires_at = duel.get("pending_expires_at")
    if pending_expires_at and status == "pending" and pending_expires_at <= now:
        execute(
            "UPDATE duels SET status = 'expired', winner = 'none', updated_at = NOW() WHERE id = %s",
            (duel_id,),
        )
        return query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))

    return duel


def _evaluate_answers(question_ids: _t.List[str], answers: dict, time_taken_seconds: _t.Optional[float]) -> dict:
    answers = answers or {}
    rows = query_all(
        "SELECT question_id, answer FROM questions WHERE question_id = ANY(%s)",
        (question_ids or [],),
    ) if question_ids else []
    expected = {r["question_id"]: r.get("answer", "") for r in rows}

    correct = 0
    for qid in question_ids:
        submitted = str(answers.get(qid, "") or "").strip().lower()
        real_answer = str(expected.get(qid, "") or "").strip().lower()
        if submitted and real_answer and submitted == real_answer:
            correct += 1

    return {
        "total": len(question_ids),
        "correct": correct,
        "time_taken_seconds": float(time_taken_seconds or 0),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }


def get_total_questions_count() -> int:
    """Cache the total question count to avoid counting on every request."""
    cached = cache.get(TOTAL_QUESTIONS_CACHE_KEY)
    if cached is not None:
        return cached
    row = query_one("SELECT COUNT(*) AS cnt FROM questions") or {"cnt": 0}
    total = row.get("cnt", 0) or 0
    cache.set(TOTAL_QUESTIONS_CACHE_KEY, total, TOTAL_QUESTIONS_TTL)
    return total


def get_session_options() -> list:
    """Return cached list of session codes with labels for dropdowns."""
    cached = cache.get(SESSION_OPTIONS_CACHE_KEY, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        return cached
    rows = query_all("SELECT DISTINCT session_code FROM questions ORDER BY session_code")
    session_options = [
        {
            "code": r['session_code'],
            "label": label_session(r['session_code']),
            "display": display_session_code(r['session_code']),
        }
        for r in rows
    ]
    cache.set(SESSION_OPTIONS_CACHE_KEY, session_options, SESSION_OPTIONS_TTL)
    return session_options


def update_weekly_champion():
    """
    Assign champion_theme_access to the top user by accuracy over the past 7 days.
    Highest accuracy wins; ties break by solved count then user_id. Clears previous holder.
    """
    cached = cache.get(CHAMPION_CACHE_KEY, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        return cached

    ensure_champion_access_field()

    top = query_one(
        """
        SELECT ua.user_id,
               SUM(CASE WHEN ua.correct THEN 1 ELSE 0 END) AS correct_count,
               SUM(CASE WHEN ua.solved THEN 1 ELSE 0 END) AS solved_count
        FROM user_activity ua
        WHERE ua.time_started >= NOW() - INTERVAL '7 days'
        GROUP BY ua.user_id
        HAVING SUM(CASE WHEN ua.solved THEN 1 ELSE 0 END) > 0
        ORDER BY
          (SUM(CASE WHEN ua.correct THEN 1 ELSE 0 END)::float / NULLIF(SUM(CASE WHEN ua.solved THEN 1 ELSE 0 END),0)) DESC,
          SUM(CASE WHEN ua.solved THEN 1 ELSE 0 END) DESC,
          ua.user_id ASC
        LIMIT 1;
        """
    )

    current_holders = {
        row.get("user_id")
        for row in query_all("SELECT user_id FROM users WHERE champion_theme_access = TRUE")
        if row.get("user_id")
    }

    if not top:
        if current_holders:
            execute("UPDATE users SET champion_theme_access = FALSE WHERE champion_theme_access = TRUE")
        cache.set(CHAMPION_CACHE_KEY, None, CHAMPION_CACHE_TTL)
        return None

    winner_id = top.get("user_id")

    stale_holders = [uid for uid in current_holders if uid != winner_id]
    if stale_holders:
        execute(
            "UPDATE users SET champion_theme_access = FALSE WHERE champion_theme_access = TRUE AND user_id <> %s",
            (winner_id,),
        )
    if winner_id not in current_holders:
        execute(
            "UPDATE users SET champion_theme_access = TRUE WHERE user_id = %s",
            (winner_id,),
        )

    winner = query_one(
        "SELECT user_id, name, email FROM users WHERE user_id = %s",
        (winner_id,),
    ) or {}

    display_name = winner.get("name") or winner.get("email") or "Top Solver"
    result = {"user_id": winner_id, "name": display_name}
    cache.set(CHAMPION_CACHE_KEY, result, CHAMPION_CACHE_TTL)
    return result


def question_bank(request):
    """Render the initial page with session codes."""
    session_options = get_session_options()
    return render(request, 'question_bank.html', {'session_options': session_options})


def get_subtopics(request):
    """Return subtopics for a given session code."""
    session_code = request.GET.get('session_code')
    if not session_code:
        return JsonResponse({'error': 'Session code is required'}, status=400)

    cache_key = f"subtopics:{session_code}"
    subtopics = cache.get(cache_key)
    if subtopics is None:
        rows = query_all(
            "SELECT DISTINCT subtopic FROM questions WHERE session_code = %s",
            (session_code,),
        )
        subtopics = [r['subtopic'] for r in rows]
        cache.set(cache_key, subtopics, SUBTOPIC_CACHE_TTL)
    if not subtopics:
        return JsonResponse({'error': 'No subtopics found for this session code'}, status=404)

    return JsonResponse({'subtopics': list(subtopics)})

def practice_questions(request):
    """Render the practice questions page with questions in random order."""
    session_code = request.GET.get('session_code')
    subtopic = request.GET.get('subtopic')

    if not session_code or not subtopic:
        return render(request, 'error.html', {
            'message': 'Session code and subtopic are required'
        })

    # Fetch questions from PostgreSQL matching the filters
    docs = query_all(
        "SELECT * FROM questions WHERE session_code = %s AND subtopic = %s",
        (session_code, subtopic),
    )
    random.shuffle(docs)

    user_id = request.session.get('user_id') or ""
    guest_limit = None
    if not user_id:
        guest_limit = 2
        docs = docs[:guest_limit]

    questions = [SimpleNamespace(**doc) for doc in docs]

    # ✅ Safely get user_id from session
    return render(request, 'practice_questions.html', {
        'questions': questions,
        'user_id': user_id,
        'limit': None if user_id else guest_limit,
    })


def user_stats(request):
    """Personal stats dashboard plus global leaderboard."""
    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Please log in to view your stats.")
        return redirect("login")

    user = query_one(
        "SELECT user_id, name, email, role, school FROM users WHERE user_id = %s",
        (user_id,),
    ) or {}

    stats_row = query_one(
        """
        SELECT COUNT(*) AS attempts,
               COUNT(*) FILTER (WHERE solved = TRUE) AS solved,
               COUNT(*) FILTER (WHERE correct = TRUE) AS correct,
               COUNT(*) FILTER (WHERE bookmarked = TRUE) AS bookmarked,
               COUNT(*) FILTER (WHERE starred = TRUE) AS starred,
               AVG(time_took) AS avg_time
        FROM user_activity
        WHERE user_id = %s
        """,
        (user_id,),
    ) or {}

    attempts = stats_row.get("attempts", 0) or 0
    solved_count = stats_row.get("solved", 0) or 0
    correct_count = stats_row.get("correct", 0) or 0
    incorrect_count = max(solved_count - correct_count, 0)
    accuracy = round((correct_count / solved_count) * 100, 1) if solved_count else 0.0

    avg_time_val = stats_row.get("avg_time")
    if isinstance(avg_time_val, str):
        try:
            h, m, s = avg_time_val.split(":")
            avg_seconds = int(float(h) * 3600 + float(m) * 60 + float(s))
            avg_time_val = timedelta(seconds=avg_seconds)
        except Exception:
            avg_time_val = None
    avg_time_display = None
    if avg_time_val:
        total_seconds = int(avg_time_val.total_seconds())
        minutes, seconds = divmod(total_seconds, 60)
        avg_time_display = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    # Recent attempts (join question metadata)
    recent = query_all(
        """
        SELECT ua.question_id, ua.solved, ua.correct, ua.bookmarked, ua.starred,
               ua.time_started, ua.time_took, q.session_code, q.subtopic
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        LIMIT 6
        """,
        (user_id,),
    )

    # Performance by subtopic
    by_topic_raw = query_all(
        """
        SELECT q.subtopic,
               COUNT(*) AS total,
               SUM(CASE WHEN ua.correct = TRUE THEN 1 ELSE 0 END) AS correct
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s
        GROUP BY q.subtopic
        HAVING COUNT(*) > 0
        ORDER BY total DESC
        LIMIT 5
        """,
        (user_id,),
    )
    by_topic = []
    for row in by_topic_raw:
        total = row.get("total", 0) or 0
        correct_val = row.get("correct", 0) or 0
        pct = round((correct_val / total) * 100, 1) if total else 0
        row["pct"] = pct
        by_topic.append(row)

    # Global leaderboard (by solved)
    leaderboard = query_all(
        """
        SELECT u.name, u.user_id,
               COUNT(*) FILTER (WHERE ua.solved = TRUE) AS solved,
               COUNT(*) FILTER (WHERE ua.correct = TRUE) AS correct
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        GROUP BY u.user_id, u.name
        ORDER BY solved DESC, correct DESC
        LIMIT 10
        """
    )

    bookmarked_rows = query_all(
        """
        SELECT ua.question_id, q.session_code, q.subtopic, ua.time_started
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s AND ua.bookmarked = TRUE
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        LIMIT 10
        """,
        (user_id,),
    )

    starred_rows = query_all(
        """
        SELECT ua.question_id, q.session_code, q.subtopic, ua.time_started
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s AND ua.starred = TRUE
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        LIMIT 10
        """,
        (user_id,),
    )

    saved = query_all(
        """
        SELECT q.question_id, q.image_base64, q.answer, q.session_code, q.subtopic,
               ua.bookmarked, ua.starred, ua.time_started
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s AND (ua.bookmarked = TRUE OR ua.starred = TRUE)
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        """,
        (user_id,),
    )

    streak = compute_streak(user_id)

    context = {
        "user": user,
        "stats": {
            "attempts": attempts,
            "solved": solved_count,
            "correct": correct_count,
            "incorrect": incorrect_count,
            "accuracy": accuracy,
            "bookmarked": stats_row.get("bookmarked", 0) or 0,
            "starred": stats_row.get("starred", 0) or 0,
            "avg_time": avg_time_display,
        },
        "recent": recent,
        "by_topic": by_topic,
        "leaderboard": leaderboard,
        "bookmarked_rows": bookmarked_rows,
        "starred_rows": starred_rows,
        "saved": saved,
        "streak": streak,
    }
    return render(request, "user_stats.html", context)


def leaderboard(request):
    """Public leaderboard ranked by correct answers."""
    rows = query_all(
        """
        SELECT u.user_id,
               COALESCE(NULLIF(u.name, ''), u.email) AS display_name,
               u.email,
               COUNT(*) FILTER (WHERE ua.correct = TRUE) AS correct_count,
               COUNT(*) FILTER (WHERE ua.solved = TRUE) AS solved_count,
               COUNT(*) AS attempts
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        GROUP BY u.user_id, u.name, u.email
        HAVING COUNT(*) FILTER (WHERE ua.correct = TRUE) > 0
        ORDER BY correct_count DESC, attempts DESC, display_name
        LIMIT 50
        """
    )

    leaderboard_rows = []
    for idx, row in enumerate(rows, start=1):
        solved_val = row.get("solved_count", 0) or 0
        correct_val = row.get("correct_count", 0) or 0
        incorrect_val = max(solved_val - correct_val, 0)
        leaderboard_rows.append(
            {
                "rank": idx,
                "user_id": row.get("user_id"),
                "name": row.get("display_name") or row.get("email") or "Anonymous",
                "email": row.get("email"),
                "correct": correct_val,
                "incorrect": incorrect_val,
                "solved": solved_val,
                "attempts": row.get("attempts", 0) or 0,
                "accuracy": (
                    round(
                        ((row.get("correct_count", 0) or 0) / (row.get("solved_count", 0) or 1))
                        * 100,
                        1,
                    )
                    if (row.get("solved_count", 0) or 0) > 0
                    else 0
                ),
            }
        )

    top_three = leaderboard_rows[:3]
    rest = leaderboard_rows[3:]

    return render(
        request,
        "leaderboard.html",
        {"top_three": top_three, "rest": rest, "rows": leaderboard_rows},
    )


def progress_tracker(request):
    """Allow users to track subtopic completion per session."""
    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Please log in to track your progress.")
        return redirect("login")

    ensure_study_progress_table()

    session_options = get_session_options()
    session_codes = [opt["code"] for opt in session_options]
    selected_session = request.GET.get("session") or (session_codes[0] if session_codes else None)

    subtopics = []
    if selected_session:
        subtopics = query_all(
            """
            SELECT DISTINCT subtopic
            FROM questions
            WHERE session_code = %s
            ORDER BY subtopic
            """,
            (selected_session,),
        )

    existing = {}
    if selected_session:
        for row in query_all(
            """
            SELECT subtopic, completed
            FROM study_progress
            WHERE user_id = %s AND session_code = %s
            """,
            (user_id, selected_session),
        ):
            existing[row.get("subtopic")] = row.get("completed", False)

    checklist = []
    for row in subtopics:
        label = row.get("subtopic")
        checklist.append(
            {
                "subtopic": label,
                "completed": existing.get(label, False),
            }
        )

    return render(
        request,
        "progress.html",
        {
            "sessions": session_options,
            "selected_session": selected_session,
            "checklist": checklist,
            "selected_label": label_session(selected_session) if selected_session else None,
            "selected_display": display_session_code(selected_session) if selected_session else None,
        },
    )


@require_POST
def save_progress(request):
    """Persist checklist state for a session/subtopic list."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Unauthorized"}, status=401)

    ensure_study_progress_table()

    try:
        payload: _t.Dict[str, _t.Any] = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    session_code = payload.get("session_code")
    items = payload.get("items", [])

    if not session_code or not isinstance(items, list):
        return JsonResponse({"error": "Missing session_code or items"}, status=400)

    for item in items:
        subtopic = (item or {}).get("subtopic")
        completed = bool((item or {}).get("completed"))
        if not subtopic:
            continue
        execute(
            """
            INSERT INTO study_progress (user_id, session_code, subtopic, completed, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (user_id, session_code, subtopic)
            DO UPDATE SET completed = EXCLUDED.completed, updated_at = NOW()
            """,
            (user_id, session_code, subtopic, completed),
        )

    return JsonResponse({"status": "ok"})


def saved_questions(request):
    """Practice bookmarked/starred questions quickly."""
    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Please log in to view saved questions.")
        return redirect("login")

    saved = query_all(
        """
        SELECT q.question_id, q.image_base64, q.answer, q.session_code, q.subtopic,
               ua.bookmarked, ua.starred, ua.time_started
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s AND (ua.bookmarked = TRUE OR ua.starred = TRUE)
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        """,
        (user_id,),
    )

    return render(request, "saved_questions.html", {"saved": saved, "user_id": user_id})


def about(request):
    """Simple About page for creators and site info."""
    return render(request, 'about.html')


def duels_hub(request):
    """Render the duel hub page with create/join forms."""
    ensure_duel_tables()
    session_rows = query_all("SELECT DISTINCT session_code FROM questions")
    session_options = [
        {
            "code": r["session_code"],
            "label": label_session(r["session_code"]),
            "display": display_session_code(r["session_code"]),
        }
        for r in session_rows
    ]
    prefill_code = request.GET.get("code", "").strip()
    context = {
        "session_options": session_options,
        "prefill_code": prefill_code,
        "user_id": request.session.get("user_id"),
    }
    return render(request, "duels.html", context)


def duel_play(request, duel_id: int):
    """Display a duel session with the shared question set."""
    ensure_duel_tables()
    duel = query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))
    if not duel:
        messages.error(request, "Duel not found.")
        return redirect("duels_hub")

    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Log in to join or view this duel.")
        return redirect("login")

    if user_id not in [duel.get("creator_id"), duel.get("opponent_id")]:
        messages.error(request, "You are not a participant in this duel.")
        return redirect("duels_hub")

    question_ids = _parse_json_field(duel.get("question_ids"), [])
    questions = []
    if question_ids:
        rows = query_all(
            """
            SELECT question_id, extracted_text, session_code, subtopic, image_base64
            FROM questions WHERE question_id = ANY(%s)
            """,
            (question_ids,),
        )
        # Preserve order based on question_ids
        order = {qid: idx for idx, qid in enumerate(question_ids)}
        rows.sort(key=lambda r: order.get(r["question_id"], 0))
        questions = rows

    serialized_duel = _serialize_duel(duel)
    creator_name = None
    opponent_name = None
    if duel.get("creator_id"):
        c = query_one("SELECT name, email FROM users WHERE user_id = %s", (duel.get("creator_id"),))
        creator_name = c.get("name") or c.get("email") if c else None
    if duel.get("opponent_id"):
        o = query_one("SELECT name, email FROM users WHERE user_id = %s", (duel.get("opponent_id"),))
        opponent_name = o.get("name") or o.get("email") if o else None
    context = {
        "duel": serialized_duel,
        "duel_json": json.dumps(serialized_duel),
        "questions": questions,
        "questions_json": json.dumps(questions),
        "user_id": user_id,
        "creator_name": creator_name,
        "opponent_name": opponent_name,
    }
    return render(request, "duel_detail.html", context)


# -------------------------
# API ENDPOINTS
# -------------------------

@csrf_exempt
def check_answer(request):
    """Check if a submitted answer is correct."""
    question_id = request.POST.get('question_id')
    selected_answer = request.POST.get('selected_answer')
    doc = query_one("SELECT answer FROM questions WHERE question_id = %s", (question_id,))
    is_correct = doc and doc.get('answer') == selected_answer
    return JsonResponse({'is_correct': is_correct})


@csrf_exempt
@require_POST
def api_create_duel(request):
    """Create a duel and return the party code."""
    ensure_duel_tables()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to create a duel."}, status=401)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        payload = request.POST

    syllabus_code = (payload.get("syllabus_code") or "").strip() or None
    time_limit = 0  # time limits removed; use completion speed as tiebreak

    question_count = payload.get("question_count") or payload.get("questions") or 5
    try:
        question_count = int(question_count)
    except Exception:
        question_count = 5
    question_count = max(1, min(question_count, 50))

    question_ids = _pick_question_ids(question_count, syllabus_code)
    if not question_ids:
        return JsonResponse({"error": "No questions available for that selection."}, status=400)

    code = _generate_duel_code()
    while query_one("SELECT 1 FROM duels WHERE code = %s", (code,)):
        code = _generate_duel_code()

    now = datetime.now(timezone.utc)
    pending_expires_at = now + timedelta(minutes=15)

    execute(
        """
        INSERT INTO duels (
            code, creator_id, status, syllabus_code, question_ids,
            time_limit_seconds, pending_expires_at, created_at, updated_at
        ) VALUES (%s, %s, 'pending', %s, %s, %s, %s, NOW(), NOW())
        """,
        (code, user_id, syllabus_code, json.dumps(question_ids), time_limit, pending_expires_at),
    )

    duel = query_one("SELECT * FROM duels WHERE code = %s", (code,))
    data = _serialize_duel(duel)
    data["play_url"] = f"/duels/{duel.get('id')}/"
    return JsonResponse(data)


@csrf_exempt
@require_POST
def api_join_duel(request):
    """Join a duel using the party code."""
    ensure_duel_tables()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to join a duel."}, status=401)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        payload = request.POST

    code = (payload.get("code") or "").strip().upper()
    if not code:
        return JsonResponse({"error": "Party code is required."}, status=400)

    duel = query_one("SELECT * FROM duels WHERE code = %s", (code,))
    if not duel:
        return JsonResponse({"error": "Duel not found."}, status=404)

    duel = _auto_finalize_if_needed(duel)
    if duel.get("status") != "pending":
        return JsonResponse({"error": f"Duel is {duel.get('status')}."}, status=400)

    if duel.get("creator_id") == user_id:
        return JsonResponse({"error": "You created this duel; share the code with someone else to join."}, status=400)

    execute(
        """
        UPDATE duels
        SET opponent_id = %s,
            status = 'active',
            start_at = NOW(),
            updated_at = NOW()
        WHERE id = %s
        """,
        (user_id, duel.get("id")),
    )

    duel = query_one("SELECT * FROM duels WHERE id = %s", (duel.get("id"),))
    data = _serialize_duel(duel)
    data["play_url"] = f"/duels/{duel.get('id')}/"
    return JsonResponse(data)


def api_duel_status(request, duel_id: int):
    """Return duel status for polling."""
    ensure_duel_tables()
    duel = query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))
    if not duel:
        return JsonResponse({"error": "Duel not found."}, status=404)
    duel = _auto_finalize_if_needed(duel)
    return JsonResponse(_serialize_duel(duel))


@csrf_exempt
@require_POST
def api_duel_submit(request, duel_id: int):
    """Submit answers for a duel; locks once submitted or expired."""
    ensure_duel_tables()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to submit."}, status=401)

    duel = query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))
    if not duel:
        return JsonResponse({"error": "Duel not found."}, status=404)

    duel = _auto_finalize_if_needed(duel)
    if duel.get("status") == "pending":
        return JsonResponse({"error": "Duel has not started yet."}, status=400)
    if duel.get("status") in ("completed", "expired"):
        return JsonResponse({"error": f"Duel is {duel.get('status')}."}, status=400)

    role = None
    flag_field = None
    answers_field = None
    score_field = None
    if duel.get("creator_id") == user_id:
        role = "creator"
        flag_field = "creator_submitted"
        answers_field = "creator_answers"
        score_field = "creator_score"
    elif duel.get("opponent_id") == user_id:
        role = "opponent"
        flag_field = "opponent_submitted"
        answers_field = "opponent_answers"
        score_field = "opponent_score"
    else:
        return JsonResponse({"error": "You are not a participant in this duel."}, status=403)

    if duel.get(flag_field):
        return JsonResponse({"error": "Already submitted."}, status=400)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        payload = {}

    answers = payload.get("answers") or {}
    time_taken_seconds = payload.get("time_taken_seconds") or payload.get("time_taken") or 0

    question_ids = _parse_json_field(duel.get("question_ids"), [])
    score = _evaluate_answers(question_ids, answers, time_taken_seconds)

    execute(
        f"""
        UPDATE duels
        SET {flag_field} = TRUE,
            {answers_field} = %s,
            {score_field} = %s,
            updated_at = NOW()
        WHERE id = %s
        """,
        (json.dumps(answers), json.dumps(score), duel_id),
    )

    duel = query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))

    if duel.get("creator_submitted") and duel.get("opponent_submitted"):
        winner = _compute_winner(duel, expired=False)
        execute(
            "UPDATE duels SET status = 'completed', winner = %s, updated_at = NOW() WHERE id = %s",
            (winner, duel_id),
        )
        duel = query_one("SELECT * FROM duels WHERE id = %s", (duel_id,))
    else:
        duel = _auto_finalize_if_needed(duel)

    return JsonResponse(_serialize_duel(duel))

@csrf_exempt
@require_POST
def update_activity(request):
    """Stateless JSON API to update or record user activity for a question."""
    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    user_id = data.get("user_id")
    question_id = data.get("question_id")
    action = data.get("action")

    if not user_id or not question_id or not action:
        return JsonResponse({"error": "Missing user_id, question_id, or action"}, status=400)

    # Ensure user exists
    user = query_one("SELECT * FROM users WHERE user_id = %s", (user_id,))
    if not user:
        return JsonResponse({"error": "User not found"}, status=404)

    # Ensure activity row exists
    activity = get_or_create_activity(user_id, question_id)
    updates = {}

    if action == "start":
        # Use timezone-aware timestamp to avoid naive/aware issues
        now = datetime.now(timezone.utc)
        updates["time_started"] = now.isoformat()
        execute(
            "UPDATE user_activity SET time_started = %s, times_viewed = times_viewed + 1 WHERE user_id = %s AND question_id = %s",
            (now, user_id, question_id),
        )
    elif action == "answer":
        # Lock in the first submitted answer to prevent correcting accuracy by retrying
        if activity.get("solved"):
            return JsonResponse(
                {
                    "status": "ignored",
                    "already_solved": True,
                    "correct": bool(activity.get("correct")),
                }
            )
        correct = bool(data.get("correct", False))
        time_took = None
        started = activity.get("time_started")
        if started:
            # Ensure both datetimes are timezone-aware before subtraction
            now = datetime.now(timezone.utc)
            if getattr(started, "tzinfo", None) is None:
                started = started.replace(tzinfo=timezone.utc)
            time_took = now - started
            updates["time_took"] = str(time_took)
        updates.update({"solved": True, "correct": correct})
        execute(
            "UPDATE user_activity SET solved = %s, correct = %s, time_took = %s WHERE user_id = %s AND question_id = %s",
            (True, correct, time_took, user_id, question_id),
        )
        invalidate_streak_cache(user_id)
    elif action == "bookmark":
        new_state = not activity.get("bookmarked", False)
        updates["bookmarked"] = new_state
        execute(
            "UPDATE user_activity SET bookmarked = %s WHERE user_id = %s AND question_id = %s",
            (new_state, user_id, question_id),
        )
    elif action == "star":
        new_state = not activity.get("starred", False)
        updates["starred"] = new_state
        execute(
            "UPDATE user_activity SET starred = %s WHERE user_id = %s AND question_id = %s",
            (new_state, user_id, question_id),
        )
    else:
        return JsonResponse({"error": "Invalid action"}, status=400)

    return JsonResponse({"status": "ok", **updates})


# -------------------------
# ADMIN VIEWS
# -------------------------

@staff_member_required
def user_activity_admin(request):
    """Display user activity records with summary statistics for admins."""
    def seconds_from_interval(value):
        if value is None:
            return None
        if hasattr(value, "total_seconds"):
            return float(value.total_seconds())
        try:
            return float(value)
        except Exception:
            return None

    def humanize_seconds(seconds):
        if seconds is None:
            return None
        total = int(seconds)
        minutes, secs = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    filters = {
        "query": request.GET.get("q", "").strip(),
        "status": request.GET.get("status", ""),
        "correctness": request.GET.get("correctness", ""),
        "saved": request.GET.get("saved", ""),
        "range": request.GET.get("range", "all"),
        "min_views": request.GET.get("min_views", ""),
    }

    conditions = []
    params = []

    if filters["query"]:
        term = f"%{filters['query'].lower()}%"
        conditions.append(
            "(LOWER(u.name) LIKE %s OR LOWER(u.email) LIKE %s OR ua.user_id ILIKE %s OR ua.question_id ILIKE %s OR LOWER(q.subtopic) LIKE %s OR LOWER(q.session_code) LIKE %s)"
        )
        params.extend([term, term, term, term, term, term])

    if filters["status"] == "solved":
        conditions.append("ua.solved = TRUE")
    elif filters["status"] == "unsolved":
        conditions.append("ua.solved = FALSE")

    if filters["correctness"] == "correct":
        conditions.append("ua.correct = TRUE")
    elif filters["correctness"] == "incorrect":
        conditions.append("ua.correct = FALSE")

    if filters["saved"] == "bookmarked":
        conditions.append("ua.bookmarked = TRUE")
    elif filters["saved"] == "starred":
        conditions.append("ua.starred = TRUE")

    range_map = {"7d": 7, "30d": 30, "90d": 90}
    if filters["range"] in range_map:
        start_time = datetime.now(timezone.utc) - timedelta(days=range_map[filters["range"]])
        conditions.append("ua.time_started >= %s")
        params.append(start_time)

    if filters["min_views"].isdigit():
        conditions.append("ua.times_viewed >= %s")
        params.append(int(filters["min_views"]))
    else:
        filters["min_views"] = ""

    where_sql = " AND ".join(conditions) if conditions else "TRUE"
    params_tuple = tuple(params)

    records_raw = query_all(
        f"""
        SELECT ua.*, u.name AS user_name, u.email, q.session_code, q.subtopic, q.year, q.paper_code
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        JOIN questions q ON q.question_id = ua.question_id
        WHERE {where_sql}
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        LIMIT 300
        """,
        params_tuple,
    )

    for row in records_raw:
        row["time_spent_seconds"] = seconds_from_interval(row.get("time_took"))
        row["time_spent_display"] = humanize_seconds(row.get("time_spent_seconds"))
        if row.get("correct"):
            row["result_label"] = "Correct"
        elif row.get("solved"):
            row["result_label"] = "Solved"
        else:
            row["result_label"] = "In progress"

    records = [SimpleNamespace(**row) for row in records_raw]

    filtered_row = query_one(
        f"""
        SELECT
            COUNT(*) AS total_records,
            COUNT(*) FILTER (WHERE ua.solved = TRUE) AS solved,
            COUNT(*) FILTER (WHERE ua.correct = TRUE) AS correct,
            COUNT(*) FILTER (WHERE ua.bookmarked = TRUE) AS bookmarked,
            COUNT(*) FILTER (WHERE ua.starred = TRUE) AS starred,
            AVG(ua.times_viewed) AS avg_views,
            EXTRACT(EPOCH FROM AVG(ua.time_took)) AS avg_time_seconds
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        JOIN questions q ON q.question_id = ua.question_id
        WHERE {where_sql}
        """,
        params_tuple,
    ) or {}

    solved_count = filtered_row.get("solved", 0) or 0
    correct_count = filtered_row.get("correct", 0) or 0
    filtered_summary = {
        "total_records": filtered_row.get("total_records", 0) or 0,
        "solved": solved_count,
        "correct": correct_count,
        "bookmarked": filtered_row.get("bookmarked", 0) or 0,
        "starred": filtered_row.get("starred", 0) or 0,
        "accuracy": round((correct_count / solved_count) * 100, 1) if solved_count else 0.0,
        "avg_views": round(filtered_row.get("avg_views", 0) or 0, 1),
        "avg_time_display": humanize_seconds(filtered_row.get("avg_time_seconds")),
    }

    summary = {
        "total_users": query_one("SELECT COUNT(*) AS cnt FROM users")['cnt'],
        "total_questions": query_one("SELECT COUNT(*) AS cnt FROM questions")['cnt'],
        "total_records": query_one("SELECT COUNT(*) AS cnt FROM user_activity")['cnt'],
        "solved": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE solved = TRUE")['cnt'],
        "correct": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE correct = TRUE")['cnt'],
        "starred": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE starred = TRUE")['cnt'],
        "bookmarked": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE bookmarked = TRUE")['cnt'],
    }

    top_subtopics_raw = query_all(
        f"""
        SELECT q.subtopic,
               COUNT(*) AS attempts,
               COUNT(*) FILTER (WHERE ua.correct = TRUE) AS correct,
               COUNT(*) FILTER (WHERE ua.solved = TRUE) AS solved
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        JOIN questions q ON q.question_id = ua.question_id
        WHERE {where_sql}
        GROUP BY q.subtopic
        ORDER BY attempts DESC
        LIMIT 6
        """,
        params_tuple,
    )
    top_subtopics = []
    for row in top_subtopics_raw:
        attempts = row.get("attempts", 0) or 0
        correct_val = row.get("correct", 0) or 0
        accuracy = round((correct_val / attempts) * 100, 1) if attempts else 0
        row["accuracy"] = accuracy
        top_subtopics.append(row)

    top_users_raw = query_all(
        f"""
        SELECT u.user_id, u.name, u.email,
               COUNT(*) AS attempts,
               COUNT(*) FILTER (WHERE ua.solved = TRUE) AS solved,
               COUNT(*) FILTER (WHERE ua.correct = TRUE) AS correct
        FROM user_activity ua
        JOIN users u ON u.user_id = ua.user_id
        JOIN questions q ON q.question_id = ua.question_id
        WHERE {where_sql}
        GROUP BY u.user_id, u.name, u.email
        ORDER BY solved DESC, correct DESC, attempts DESC
        LIMIT 5
        """,
        params_tuple,
    )
    top_users = []
    for row in top_users_raw:
        solved_val = row.get("solved", 0) or 0
        correct_val = row.get("correct", 0) or 0
        row["accuracy"] = round((correct_val / solved_val) * 100, 1) if solved_val else 0
        top_users.append(row)

    filters["range_label"] = {"7d": "Past 7 days", "30d": "Past 30 days", "90d": "Past 90 days"}.get(filters["range"], "All time")
    filters["has_active"] = any([
        filters["query"],
        filters["status"],
        filters["correctness"],
        filters["saved"],
        filters["range"] in range_map,
        filters["min_views"],
    ])

    context = {
        "records": records,
        "summary": summary,
        "filtered": filtered_summary,
        "filters": filters,
        "top_subtopics": top_subtopics,
        "top_users": top_users,
    }

    return render(request, "user_activity_admin.html", context)


@staff_member_required
def staff_reset_password(request):
    """Allow staff to overwrite a user's password and issue a temp password."""
    users = query_all("SELECT user_id, name, email FROM users ORDER BY email")
    generated = None
    target = None
    selected_user_id = None

    prefill_email = request.GET.get("email", "").strip()
    if prefill_email:
        for u in users:
            if u.get("email", "").lower() == prefill_email.lower():
                selected_user_id = u.get("user_id")
                break

    if request.method == "POST":
        target_id = request.POST.get("user_id", "").strip()
        new_password = request.POST.get("new_password", "").strip()
        target = query_one("SELECT user_id, name, email FROM users WHERE user_id = %s", (target_id,))
        selected_user_id = target_id

        if not target:
            messages.error(request, "User not found.")
            return redirect("staff_reset_password")

        if not new_password:
            new_password = generate_temp_password()

        execute(
            "UPDATE users SET password = %s WHERE user_id = %s",
            (make_password(new_password), target_id),
        )
        generated = new_password
        messages.success(request, f"Temporary password set for {target.get('email')}.")

    return render(
        request,
        "staff_reset_password.html",
        {
            "users": users,
            "generated": generated,
            "target": target,
            "selected_user_id": selected_user_id,
            "prefill_email": prefill_email,
        },
    )


# -------------------------
# BUG REPORTING
# -------------------------

def report_bug(request):
    """Report a bug with optional screenshot."""
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        description = request.POST.get("description", "").strip()
        steps = request.POST.get("steps", "").strip()
        severity = request.POST.get("severity", "medium")
        contact_email = request.POST.get("contact_email", "").strip()
        screenshot = request.FILES.get("screenshot")

        if not title or not description:
            messages.error(request, "Title and description are required.")
            return render(request, "report_bug.html")

        BugReport.objects.create(
            title=title,
            description=description,
            steps_to_reproduce=steps,
            severity=severity,
            contact_email=contact_email,
            screenshot=screenshot,
        )
        return redirect("report_bug_thanks")

    return render(request, "report_bug.html")


def report_bug_thanks(request):
    """Thank-you page after bug submission."""
    return render(request, "bug_thanks.html")


@staff_member_required
def staff_bug_list(request):
    """Admin view for bug reports list."""
    bugs = BugReport.objects.order_by("-created_at")
    return render(request, "staff_bug_list.html", {"bugs": bugs})


@staff_member_required
def staff_bug_detail(request, bug_id: int):
    """Admin view for bug report details."""
    bug = BugReport.objects.filter(id=bug_id).first()
    if not bug:
        messages.error(request, "Bug not found")
        return redirect("staff_bug_list")
    # Use app templates loader (APP_DIRS) — template lives at main/templates/staff_bug_detail.html
    return render(request, "staff_bug_detail.html", {"bug": bug})


@staff_member_required
@require_POST
def staff_bug_update_status(request, bug_id: int):
    """Update a bug's status (e.g., close or reopen)."""
    new_status = request.POST.get("status", "").strip().lower()
    next_url = request.POST.get("next")
    allowed_statuses = {"open", "in_progress", "closed", "resolved"}

    bug = BugReport.objects.filter(id=bug_id).first()
    if not bug:
        messages.error(request, "Bug not found.")
        return redirect("staff_bug_list")

    if new_status not in allowed_statuses:
        messages.error(request, "Invalid status.")
        redirect_target = next_url if next_url and next_url.startswith("/") else "staff_bug_detail"
        return redirect(redirect_target, bug_id=bug_id) if redirect_target == "staff_bug_detail" else redirect(redirect_target)

    bug.status = new_status
    bug.save(update_fields=["status", "updated_at"])
    messages.success(request, f"Bug #{bug.id} marked as {new_status}.")

    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect("staff_bug_detail", bug_id=bug_id)


@staff_member_required
def staff_password_requests(request):
    """List password reset requests for manual handling."""
    ensure_password_request_table()
    if request.method == "POST":
        action = request.POST.get("action", "").strip().lower()
        request_id = request.POST.get("request_id")
        next_url = request.POST.get("next")

        if action not in {"approve", "close"} or not request_id:
            messages.error(request, "Invalid action for password request.")
            return redirect("staff_password_requests")

        row = query_one(
            "SELECT id, email FROM password_reset_requests WHERE id = %s",
            (request_id,),
        )
        if not row:
            messages.error(request, "Password request not found.")
            return redirect("staff_password_requests")

        new_status = "approved" if action == "approve" else "closed"
        execute(
            "UPDATE password_reset_requests SET status = %s, handled_at = NOW() WHERE id = %s",
            (new_status, request_id),
        )
        label = "approved" if action == "approve" else "closed"
        messages.success(request, f"Request for {row.get('email')} {label}.")

        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect("staff_password_requests")

    rows = query_all(
        """
        SELECT id, email, reason, status, created_at, handled_at
        FROM password_reset_requests
        ORDER BY created_at DESC
        """
    )
    return render(request, "staff_password_requests.html", {"requests": rows})


@staff_member_required
def staff_theme_access(request):
    """Admin view to preview and toggle champion theme access."""
    ensure_champion_access_field()

    if request.method == "POST":
        action = request.POST.get("action")
        user_id = request.POST.get("user_id")
        if action not in {"grant", "revoke"} or not user_id:
            messages.error(request, "Invalid action.")
            return redirect("staff_theme_access")
        new_value = action == "grant"
        execute(
            "UPDATE users SET champion_theme_access = %s WHERE user_id = %s",
            (new_value, user_id),
        )
        messages.success(request, f"Theme access {'granted' if new_value else 'revoked'} for {user_id}.")
        return redirect("staff_theme_access")

    users = query_all(
        """
        SELECT user_id, name, email, role, school, COALESCE(champion_theme_access, FALSE) AS champion_theme_access
        FROM users
        ORDER BY champion_theme_access DESC, name, email
        """
    )
    return render(request, "staff_theme_access.html", {"users": users})


# -------------------------
# LEGAL PAGES
# -------------------------

def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")


def disclaimer(request):
    return render(request, "disclaimer.html")
