from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.admin.views.decorators import staff_member_required
from django.core.cache import cache
from django.db.models import F
from django.utils import timezone as django_timezone
from datetime import datetime, timezone, timedelta
import base64
import hashlib
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
from .question_images import (
    ensure_question_image_columns,
    build_question_image_src,
    apply_question_image_src_to_rows,
)
from .streaks import compute_streak, invalidate_streak_cache
from .models import BugReport, APIKey

CHAMPION_CACHE_KEY = "weekly_champion"
CHAMPION_CACHE_TTL = 1800  # 30 minutes
TOTAL_QUESTIONS_CACHE_KEY = "home_total_questions"
TOTAL_QUESTIONS_TTL = 300  # 5 minutes
SESSION_OPTIONS_CACHE_KEY = "session_options"
SESSION_OPTIONS_TTL = 600  # 10 minutes
SUBTOPIC_CACHE_TTL = 600
API_OPTIONS_CACHE_KEY = "api_options_reference"
API_OPTIONS_TTL = 600
PRACTICE_QUESTION_LIMIT = 40  # cap to avoid loading all questions at once

_study_progress_ready = False
_password_request_ready = False
_chat_table_ready = False
_ping_table_ready = False
_chat_lock_ready = False
_CACHE_MISS = object()
_question_columns_cache = None

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
        user = query_one(
            "SELECT name, champion_theme_access FROM users WHERE user_id = %s",
            (session_user_id,),
        ) or {}
        has_access = bool(user.get("champion_theme_access"))
        request.session["champion_access"] = has_access
        if has_access:
            request.session["champion_name"] = user.get("name") or champion.get("name") if champion else user.get("name")
        else:
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

def ensure_chat_table():
    """Create chat_messages table if missing."""
    global _chat_table_ready
    if _chat_table_ready:
        return
    execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            image_base64 TEXT,
            reply_to_id INTEGER,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """
    )
    execute(
        "ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS image_base64 TEXT;"
    )
    execute("ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS reply_to_id INTEGER;")
    execute(
        "ALTER TABLE chat_messages ALTER COLUMN body SET DEFAULT '';"
    )
    execute("CREATE INDEX IF NOT EXISTS idx_chat_created_at ON chat_messages (created_at DESC);")
    _chat_table_ready = True


def ensure_ping_table():
    """Create ping notifications table if missing."""
    global _ping_table_ready
    if _ping_table_ready:
        return
    execute(
        """
        CREATE TABLE IF NOT EXISTS chat_pings (
            id SERIAL PRIMARY KEY,
            target_user_id VARCHAR(255) NOT NULL,
            from_user_id VARCHAR(255) NOT NULL,
            message TEXT,
            chat_message_id INTEGER,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            read_at TIMESTAMPTZ
        );
        """
    )
    execute("CREATE INDEX IF NOT EXISTS idx_chat_pings_target ON chat_pings (target_user_id, read_at)")
    _ping_table_ready = True


def ensure_chat_lock_table():
    """Create chat lock table (single row) to gate chat behind a password."""
    global _chat_lock_ready
    if _chat_lock_ready:
        return
    execute(
        """
        CREATE TABLE IF NOT EXISTS chat_lock (
            id INTEGER PRIMARY KEY DEFAULT 1,
            locked BOOLEAN DEFAULT FALSE,
            password_hash TEXT
        );
        """
    )
    # Guarantee single row exists
    row = query_one("SELECT id FROM chat_lock WHERE id = 1")
    if not row:
        execute("INSERT INTO chat_lock (id, locked, password_hash) VALUES (1, FALSE, NULL)")
    _chat_lock_ready = True


def get_chat_lock():
    ensure_chat_lock_table()
    row = query_one("SELECT locked, password_hash FROM chat_lock WHERE id = 1")
    return row or {"locked": False, "password_hash": None}


def set_chat_lock(locked: bool, password: str | None, existing_hash: str | None = None):
    ensure_chat_lock_table()
    if locked:
        if password:
            pwd_hash = make_password(password)
        else:
            pwd_hash = existing_hash
    else:
        pwd_hash = None
    execute(
        "UPDATE chat_lock SET locked = %s, password_hash = %s WHERE id = 1",
        (locked, pwd_hash),
    )

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


def _build_duel_comparison(duel: dict, user_id: _t.Optional[str] = None) -> list:
    """
    Build a question-by-question comparison payload with answers and saved states.
    Only call after the duel is over.
    """
    question_ids = _parse_json_field(duel.get("question_ids"), [])
    if not question_ids:
        return []
    ensure_question_image_columns()

    rows = query_all(
        """
        SELECT question_id, extracted_text, session_code, subtopic, image_base64, image_url, answer
        FROM questions WHERE question_id = ANY(%s)
        """,
        (question_ids,),
    )
    question_map = {r["question_id"]: r for r in rows}

    creator_answers = _parse_json_field(duel.get("creator_answers"), {}) or {}
    opponent_answers = _parse_json_field(duel.get("opponent_answers"), {}) or {}

    saved = {}
    if user_id:
        saved_rows = query_all(
            "SELECT question_id, bookmarked, starred FROM user_activity WHERE user_id = %s AND question_id = ANY(%s)",
            (user_id, question_ids),
        )
        saved = {r["question_id"]: r for r in saved_rows}

    comparison = []
    for idx, qid in enumerate(question_ids, start=1):
        meta = question_map.get(qid, {})
        correct_answer = meta.get("answer")
        creator_answer = creator_answers.get(qid)
        opponent_answer = opponent_answers.get(qid)
        correct_norm = (correct_answer or "").strip().lower()

        def _is_correct(answer_val):
            if answer_val is None:
                return False
            return (str(answer_val) or "").strip().lower() == correct_norm

        saved_meta = saved.get(qid, {})
        image_src = build_question_image_src(meta.get("image_url"), meta.get("image_base64"))
        comparison.append(
            {
                "order": idx,
                "question_id": qid,
                "text": meta.get("extracted_text"),
                "session_code": meta.get("session_code"),
                "subtopic": meta.get("subtopic"),
                "image_url": meta.get("image_url"),
                "image_base64": meta.get("image_base64"),
                "image_src": image_src,
                "correct_answer": correct_answer,
                "creator_answer": creator_answer,
                "opponent_answer": opponent_answer,
                "creator_correct": _is_correct(creator_answer),
                "opponent_correct": _is_correct(opponent_answer),
                "bookmarked": bool(saved_meta.get("bookmarked")),
                "starred": bool(saved_meta.get("starred")),
            }
        )

    return comparison


def _duel_response_payload(duel: dict, user_id: _t.Optional[str] = None) -> dict:
    """Base serializer with optional comparison details when duel is over."""
    data = _serialize_duel(duel)
    if (
        duel.get("status") in ("completed", "expired")
        and user_id
        and user_id in [duel.get("creator_id"), duel.get("opponent_id")]
    ):
        data["comparison"] = _build_duel_comparison(duel, user_id)
    return data


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

    if not top:
        cache.set(CHAMPION_CACHE_KEY, None, CHAMPION_CACHE_TTL)
        return None

    winner_id = top.get("user_id")

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


def api_options_reference(request):
    """URL-only reference page with all available API filter options."""
    cached = cache.get(API_OPTIONS_CACHE_KEY, _CACHE_MISS)
    if cached is _CACHE_MISS:
        session_code_rows = query_all("SELECT DISTINCT session_code FROM questions ORDER BY session_code")
        session_rows = query_all("SELECT DISTINCT session FROM questions ORDER BY session")
        year_rows = query_all("SELECT DISTINCT year FROM questions ORDER BY year DESC")
        paper_code_rows = query_all("SELECT DISTINCT paper_code FROM questions ORDER BY paper_code")
        variant_rows = query_all("SELECT DISTINCT variant FROM questions ORDER BY variant")
        answer_rows = query_all("SELECT DISTINCT answer FROM questions ORDER BY answer")
        subtopic_rows = query_all("SELECT DISTINCT subtopic FROM questions ORDER BY subtopic")

        session_codes = [str(row.get("session_code") or "") for row in session_code_rows if row.get("session_code") is not None]
        session_values = [str(row.get("session") or "") for row in session_rows if row.get("session")]
        year_values = [int(row.get("year")) for row in year_rows if row.get("year") is not None]
        paper_codes = [str(row.get("paper_code") or "") for row in paper_code_rows if row.get("paper_code")]
        variants = [str(row.get("variant") or "") for row in variant_rows if row.get("variant")]
        answers = [str(row.get("answer") or "") for row in answer_rows if row.get("answer")]
        subtopics = [str(row.get("subtopic") or "") for row in subtopic_rows if row.get("subtopic")]

        subject_options = []
        for code in session_codes:
            subject_options.append(
                {
                    "subject": label_session(code),
                    "session_code": code,
                    "display_code": display_session_code(code),
                }
            )

        query_params = [
            {"name": "api_key", "description": "API key in URL (fallback when header control is not available)."},
            {"name": "q", "description": "Text search across major fields."},
            {"name": "question_id", "description": "Exact question id match."},
            {"name": "subject", "description": "Biology/Chemistry/Physics or session code alias (610/620/625)."},
            {"name": "session_code", "description": "Exact syllabus code filter."},
            {"name": "session", "description": "Exam session (e.g., Oct/Nov)."},
            {"name": "year", "description": "Exam year (integer)."},
            {"name": "paper_code", "description": "Exact paper code filter."},
            {"name": "variant", "description": "Exact variant filter."},
            {"name": "subtopic", "description": "Exact subtopic filter."},
            {"name": "question_type", "description": "Alias filter (same values as subtopic)."},
            {"name": "answer", "description": "Exact answer filter."},
            {"name": "limit", "description": "Page size (default 50, max 500)."},
            {"name": "offset", "description": "Pagination offset."},
            {"name": "order_by", "description": "Sort column name from questions table."},
            {"name": "sort", "description": "Sort direction: asc or desc."},
            {"name": "include_image_base64", "description": "1 to include base64; 0 to exclude heavy payload."},
        ]

        cached = {
            "subject_options": subject_options,
            "session_codes": session_codes,
            "sessions": session_values,
            "years": year_values,
            "paper_codes": paper_codes,
            "variants": variants,
            "answers": answers,
            "subtopics": subtopics,
            "query_params": query_params,
            "order_by_options": sorted(_get_question_table_columns()),
            "subtopic_count": len(subtopics),
            "reference_url": request.build_absolute_uri("/api/questions/"),
        }
        cache.set(API_OPTIONS_CACHE_KEY, cached, API_OPTIONS_TTL)

    return render(request, "api_options_reference.html", cached)


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
    # Return an empty list instead of an error to allow "all subtopics" flows
    return JsonResponse({'subtopics': list(subtopics or [])})

def practice_questions(request):
    """Render practice questions with flexible filtering and random ordering."""
    ensure_question_image_columns()
    session_code = (request.GET.get('session_code') or "").strip()
    subtopic = (request.GET.get('subtopic') or "").strip()
    limit_override = request.GET.get('limit')
    try:
        limit = max(1, min(int(limit_override), 200)) if limit_override else PRACTICE_QUESTION_LIMIT
    except (TypeError, ValueError):
        limit = PRACTICE_QUESTION_LIMIT

    # Build filtered query; select only needed columns and randomize in SQL
    conditions = []
    params = []
    if session_code:
        conditions.append("session_code = %s")
        params.append(session_code)
    if subtopic:
        conditions.append("subtopic = %s")
        params.append(subtopic)
    where_sql = " AND ".join(conditions) if conditions else "TRUE"

    docs = query_all(
        f"""
        SELECT question_id, image_base64, image_url, answer, session_code, subtopic
        FROM questions
        WHERE {where_sql}
        ORDER BY RANDOM()
        LIMIT %s
        """,
        tuple(params + [limit]),
    )
    apply_question_image_src_to_rows(docs)

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
    ensure_question_image_columns()
    user_id = request.session.get("user_id")
    if not user_id:
        messages.info(request, "Please log in to view saved questions.")
        return redirect("login")

    saved = query_all(
        """
        SELECT q.question_id, q.image_base64, q.image_url, q.answer, q.session_code, q.subtopic,
               ua.bookmarked, ua.starred, ua.time_started
        FROM user_activity ua
        JOIN questions q ON q.question_id = ua.question_id
        WHERE ua.user_id = %s AND (ua.bookmarked = TRUE OR ua.starred = TRUE)
        ORDER BY COALESCE(ua.time_started, NOW()) DESC
        """,
        (user_id,),
    )
    apply_question_image_src_to_rows(saved)

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
    ensure_question_image_columns()
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
            SELECT question_id, extracted_text, session_code, subtopic, image_base64, image_url
            FROM questions WHERE question_id = ANY(%s)
            """,
            (question_ids,),
        )
        # Preserve order based on question_ids
        order = {qid: idx for idx, qid in enumerate(question_ids)}
        rows.sort(key=lambda r: order.get(r["question_id"], 0))
        apply_question_image_src_to_rows(rows)
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
    comparison = []
    if duel.get("status") in ("completed", "expired"):
        comparison = _build_duel_comparison(duel, user_id)
    context = {
        "duel": serialized_duel,
        "duel_json": json.dumps(serialized_duel),
        "questions": questions,
        "questions_json": json.dumps(questions),
        "comparison_json": json.dumps(comparison),
        "user_id": user_id,
        "creator_name": creator_name,
        "opponent_name": opponent_name,
    }
    return render(request, "duel_detail.html", context)


# -------------------------
# API ENDPOINTS
# -------------------------

def _extract_api_key(request) -> str:
    """Read API key from standard headers."""
    # Query param support for clients that cannot set custom headers.
    key_from_query = (
        request.GET.get("api_key")
        or request.GET.get("apikey")
        or request.GET.get("key")
        or ""
    ).strip()
    if key_from_query:
        return key_from_query

    direct = (request.headers.get("X-API-Key") or request.META.get("HTTP_X_API_KEY") or "").strip()
    if direct:
        return direct

    auth_header = (request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION") or "").strip()
    if not auth_header:
        return ""

    parts = auth_header.split(" ", 1)
    if len(parts) == 2 and parts[0].strip().lower() in {"bearer", "api-key", "apikey", "token"}:
        return parts[1].strip()
    return ""


def _require_api_key(request) -> _t.Optional[JsonResponse]:
    """Validate API key for external API endpoints."""
    raw_key = _extract_api_key(request)
    if not raw_key:
        return JsonResponse(
            {"error": "API key required. Send X-API-Key header or Authorization: Bearer <key>."},
            status=401,
        )

    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    api_key = APIKey.objects.filter(key_hash=key_hash, is_active=True).first()
    if not api_key:
        return JsonResponse({"error": "Invalid API key."}, status=401)

    now = django_timezone.now()
    if api_key.expires_at and api_key.expires_at <= now:
        return JsonResponse({"error": "API key has expired."}, status=401)

    if (
        api_key.access_mode == APIKey.ACCESS_MODE_LIMITED
        and api_key.request_limit is not None
        and api_key.usage_count >= api_key.request_limit
    ):
        return JsonResponse({"error": "API key request limit reached."}, status=401)

    # Keep usage + last_used timestamp updated.
    APIKey.objects.filter(pk=api_key.pk).update(last_used_at=now, usage_count=F("usage_count") + 1)

    request.api_key = api_key
    return None


def _truthy_param(raw_val: _t.Any) -> bool:
    """Parse common truthy query-parameter forms."""
    return str(raw_val or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_int_param(raw_val: _t.Any, default: int, minimum: int, maximum: int) -> int:
    """Safely parse and clamp integer query parameters."""
    try:
        parsed = int(raw_val)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _get_question_table_columns() -> set:
    """Read questions table columns once for dynamic filtering support."""
    global _question_columns_cache
    if _question_columns_cache is not None:
        return _question_columns_cache
    rows = query_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'questions'
          AND table_schema = current_schema()
        ORDER BY ordinal_position
        """
    )
    _question_columns_cache = {r.get("column_name") for r in rows if r.get("column_name")}
    return _question_columns_cache


def _build_absolute_image_link(request, image_url: _t.Optional[str], image_base64: _t.Optional[str]) -> _t.Optional[str]:
    """Return an absolute URL-like image link when possible."""
    image_src = build_question_image_src(image_url, image_base64)
    if not image_src:
        return None
    if image_src.startswith(("http://", "https://", "data:")):
        return image_src
    if image_src.startswith("//"):
        return f"{request.scheme}:{image_src}"
    normalized = image_src if image_src.startswith("/") else f"/{image_src}"
    return request.build_absolute_uri(normalized)


def _serialize_question_api_row(request, row: dict) -> dict:
    """Normalize outgoing question payload for external consumers."""
    payload = dict(row or {})
    payload["image_link"] = _build_absolute_image_link(
        request,
        payload.get("image_url"),
        payload.get("image_base64"),
    )
    payload["image_src"] = payload["image_link"]
    if not payload.get("question"):
        payload["question"] = payload.get("extracted_text") or payload.get("file_question")
    if not payload.get("question_type"):
        payload["question_type"] = payload.get("subtopic")
    if not payload.get("subject"):
        payload["subject"] = payload.get("session") or label_session(str(payload.get("session_code") or ""))
    return payload


def _resolve_subject_to_session_code(subject_value: str) -> _t.Optional[str]:
    """Map subject label/code input to canonical session code."""
    raw = (subject_value or "").strip()
    if not raw:
        return None

    normalized_subject = raw.lower()
    subject_to_code = {
        label.strip().lower(): code
        for code, label in SESSION_LABELS.items()
    }
    if normalized_subject in subject_to_code:
        return subject_to_code[normalized_subject]

    if raw.isdigit():
        normalized_code = raw.lstrip("0") or raw
        if normalized_code in SESSION_LABELS:
            return normalized_code

    return None


def _build_question_api_filters(request, available_columns: set) -> tuple[list[str], list]:
    """Build SQL WHERE clauses from supported query parameters."""
    eq_filters = (
        ("question_id", "question_id"),
        ("session_code", "session_code"),
        ("session", "session"),
        ("year", "year"),
        ("paper_code", "paper_code"),
        ("variant", "variant"),
        ("subtopic", "subtopic"),
        ("question_type", "question_type"),
        ("answer", "answer"),
    )
    conditions = []
    params = []

    for param_name, column_name in eq_filters:
        if column_name not in available_columns:
            continue
        raw_value = (request.GET.get(param_name) or "").strip()
        if not raw_value:
            continue

        if column_name == "year":
            try:
                raw_value = int(raw_value)
            except ValueError as exc:
                raise ValueError("year must be an integer.") from exc

        conditions.append(f"{column_name} = %s")
        params.append(raw_value)

    # subject is an alias mapped from session_code for known syllabus labels.
    subject_value = (request.GET.get("subject") or "").strip()
    if subject_value:
        subject_code = _resolve_subject_to_session_code(subject_value)

        if subject_code and "session_code" in available_columns:
            conditions.append("session_code = %s")
            params.append(subject_code)
        elif "subject" in available_columns:
            conditions.append("subject = %s")
            params.append(subject_value)
        else:
            valid_subjects = ", ".join(sorted(set(SESSION_LABELS.values())))
            raise ValueError(f"Invalid subject. Use one of: {valid_subjects}.")

    search_term = (request.GET.get("q") or "").strip()
    if search_term:
        searchable_columns = [
            "question_id",
            "session_code",
            "session",
            "year",
            "paper_code",
            "variant",
            "subtopic",
            "subject",
            "question_type",
            "file_question",
            "extracted_text",
            "answer",
            "image_key",
            "image_url",
        ]
        active_search_columns = [c for c in searchable_columns if c in available_columns]
        if active_search_columns:
            search_sql = " OR ".join(f"CAST({col} AS TEXT) ILIKE %s" for col in active_search_columns)
            conditions.append(f"({search_sql})")
            params.extend([f"%{search_term}%"] * len(active_search_columns))

    return conditions, params


def api_subtopics(request):
    """
    Return all distinct subtopics for import flows.

    Query params:
    - subject (Biology/Chemistry/Physics or 610/620/625)
    - session_code
    - session
    - q (subtopic search)
    """
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed."}, status=405)
    auth_error = _require_api_key(request)
    if auth_error:
        return auth_error

    available_columns = _get_question_table_columns()
    if "subtopic" not in available_columns:
        return JsonResponse({"error": "Subtopic field is unavailable."}, status=500)

    conditions = []
    params = []

    raw_subject = (request.GET.get("subject") or "").strip()
    raw_session_code = (request.GET.get("session_code") or "").strip()
    raw_session = (request.GET.get("session") or "").strip()
    search_q = (request.GET.get("q") or "").strip()

    if raw_subject:
        subject_code = _resolve_subject_to_session_code(raw_subject)
        if not subject_code:
            valid_subjects = ", ".join(sorted(set(SESSION_LABELS.values())))
            return JsonResponse({"error": f"Invalid subject. Use one of: {valid_subjects}."}, status=400)
        if "session_code" in available_columns:
            conditions.append("session_code = %s")
            params.append(subject_code)

    if raw_session_code and "session_code" in available_columns:
        normalized_code = raw_session_code.lstrip("0") or raw_session_code
        if raw_session_code.isdigit() and normalized_code in SESSION_LABELS:
            conditions.append("session_code = %s")
            params.append(normalized_code)
        else:
            conditions.append("session_code = %s")
            params.append(raw_session_code)

    if raw_session and "session" in available_columns:
        conditions.append("session = %s")
        params.append(raw_session)

    if search_q:
        conditions.append("subtopic ILIKE %s")
        params.append(f"%{search_q}%")

    where_sql = " AND ".join(conditions) if conditions else "TRUE"
    rows = query_all(
        f"""
        SELECT DISTINCT session_code, subtopic
        FROM questions
        WHERE {where_sql}
        ORDER BY session_code, subtopic
        """,
        tuple(params),
    )

    grouped = {}
    for row in rows:
        code = str(row.get("session_code") or "")
        subtopic = str(row.get("subtopic") or "").strip()
        if not subtopic:
            continue
        if code not in grouped:
            grouped[code] = {
                "session_code": code,
                "display_code": display_session_code(code),
                "subject": label_session(code),
                "subtopics": [],
            }
        grouped[code]["subtopics"].append(subtopic)

    by_session_code = list(grouped.values())
    all_subtopics = sorted(
        {
            item
            for group in by_session_code
            for item in group.get("subtopics", [])
            if item
        }
    )

    return JsonResponse(
        {
            "count": len(all_subtopics),
            "subtopics": all_subtopics,
            "by_session_code": by_session_code,
            "filters": {
                "subject": raw_subject or None,
                "session_code": raw_session_code or None,
                "session": raw_session or None,
                "q": search_q or None,
            },
        }
    )


def api_questions(request):
    """
    List question records with full database fields and a frontend-ready image link.

    Query params:
    - q: text search over major fields
    - question_id, session_code, session, year, paper_code, variant, subtopic, subject, question_type, answer
    - limit (default 50, max 500), offset (default 0)
    - order_by (column), sort (asc|desc)
    - include_image_base64 (1/0, defaults to 1)
    """
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed."}, status=405)
    auth_error = _require_api_key(request)
    if auth_error:
        return auth_error
    ensure_question_image_columns()

    available_columns = _get_question_table_columns()

    try:
        conditions, params = _build_question_api_filters(request, available_columns)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    limit = _parse_int_param(request.GET.get("limit"), default=50, minimum=1, maximum=500)
    offset = _parse_int_param(request.GET.get("offset"), default=0, minimum=0, maximum=1_000_000)
    include_image_base64 = _truthy_param(request.GET.get("include_image_base64", "1"))

    if "question_id" in available_columns:
        default_order = "question_id"
    elif "year" in available_columns:
        default_order = "year"
    elif available_columns:
        default_order = sorted(available_columns)[0]
    else:
        return JsonResponse({"error": "Questions table columns are unavailable."}, status=500)

    order_by = (request.GET.get("order_by") or default_order).strip()
    if order_by not in available_columns:
        order_by = default_order
    sort_direction = (request.GET.get("sort") or "asc").strip().lower()
    if sort_direction not in {"asc", "desc"}:
        sort_direction = "asc"

    where_sql = " AND ".join(conditions) if conditions else "TRUE"

    count_row = query_one(
        f"SELECT COUNT(*) AS cnt FROM questions WHERE {where_sql}",
        tuple(params),
    ) or {"cnt": 0}

    rows = query_all(
        f"""
        SELECT q.*
        FROM questions q
        WHERE {where_sql}
        ORDER BY {order_by} {sort_direction}
        LIMIT %s OFFSET %s
        """,
        tuple(params + [limit, offset]),
    )

    results = []
    for row in rows:
        payload = _serialize_question_api_row(request, row)
        if not include_image_base64:
            payload["image_base64"] = None
        results.append(payload)

    return JsonResponse(
        {
            "count": int(count_row.get("cnt", 0) or 0),
            "limit": limit,
            "offset": offset,
            "returned": len(results),
            "results": results,
        }
    )


def api_question_detail(request, question_id: str):
    """Return one question record with all fields and normalized image link."""
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed."}, status=405)
    auth_error = _require_api_key(request)
    if auth_error:
        return auth_error
    ensure_question_image_columns()

    row = query_one("SELECT * FROM questions WHERE question_id = %s", (question_id,))
    if not row:
        return JsonResponse({"error": "Question not found."}, status=404)

    payload = _serialize_question_api_row(request, row)
    include_image_base64 = _truthy_param(request.GET.get("include_image_base64", "1"))
    if not include_image_base64:
        payload["image_base64"] = None
    return JsonResponse(payload)


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

    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to view this duel."}, status=401)
    if user_id not in [duel.get("creator_id"), duel.get("opponent_id")]:
        return JsonResponse({"error": "You are not a participant in this duel."}, status=403)

    duel = _auto_finalize_if_needed(duel)
    return JsonResponse(_duel_response_payload(duel, user_id))


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

    return JsonResponse(_duel_response_payload(duel, user_id))

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

def _normalize_answer(value: _t.Any) -> str:
    """Normalize answer text for resilient equality checks."""
    return " ".join(str(value or "").strip().lower().split())


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
def staff_question_tester(request):
    """Admin tool to find questions quickly and verify answer correctness."""
    ensure_question_image_columns()

    question_id = (request.GET.get("question_id") or request.POST.get("question_id") or "").strip()
    query_text = (request.GET.get("q") or "").strip()

    selected = None
    search_results = []
    evaluation = None

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip().lower()
        if action == "check_answer":
            submitted_answer = (request.POST.get("submitted_answer") or "").strip()
            if not question_id:
                messages.error(request, "Question ID is required to check an answer.")
            else:
                selected = query_one(
                    """
                    SELECT question_id, session_code, session, year, paper_code, variant,
                           file_question, subtopic, extracted_text, image_base64, image_url, answer
                    FROM questions
                    WHERE question_id = %s
                    """,
                    (question_id,),
                )
                if not selected:
                    messages.error(request, "Question not found.")
                else:
                    selected["image_src"] = build_question_image_src(
                        selected.get("image_url"),
                        selected.get("image_base64"),
                    )
                    expected_answer = (selected.get("answer") or "").strip()
                    is_correct = _normalize_answer(submitted_answer) == _normalize_answer(expected_answer)
                    evaluation = {
                        "submitted_answer": submitted_answer,
                        "expected_answer": expected_answer,
                        "is_correct": is_correct,
                    }
                    if not submitted_answer:
                        messages.error(request, "Enter an answer first.")
                    elif is_correct:
                        messages.success(request, "Answer is correct.")
                    else:
                        messages.error(request, "Answer is incorrect.")

    if question_id and not selected:
        selected = query_one(
            """
            SELECT question_id, session_code, session, year, paper_code, variant,
                   file_question, subtopic, extracted_text, image_base64, image_url, answer
            FROM questions
            WHERE question_id = %s
            """,
            (question_id,),
        )
        if selected:
            selected["image_src"] = build_question_image_src(
                selected.get("image_url"),
                selected.get("image_base64"),
            )
            search_results = [selected]
        else:
            messages.warning(request, f"No question found for ID '{question_id}'.")
    elif query_text:
        term = f"%{query_text}%"
        search_results = query_all(
            """
            SELECT question_id, session_code, session, year, paper_code, variant, subtopic,
                   LEFT(extracted_text, 220) AS extracted_preview
            FROM questions
            WHERE extracted_text ILIKE %s
               OR file_question ILIKE %s
               OR question_id ILIKE %s
            ORDER BY year DESC, question_id
            LIMIT 120
            """,
            (term, term, term),
        )

    # Add display helpers.
    for row in search_results:
        row["subject_label"] = label_session(str(row.get("session_code") or ""))

    if selected:
        selected["subject_label"] = label_session(str(selected.get("session_code") or ""))

    context = {
        "filters": {
            "question_id": question_id,
            "q": query_text,
        },
        "search_results": search_results,
        "selected_question": selected,
        "evaluation": evaluation,
    }
    return render(request, "staff_question_tester.html", context)


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


@staff_member_required
def staff_api_keys(request):
    """Manage API keys from custom staff panel (outside Django admin)."""
    generated_key = request.session.pop("staff_api_generated_key", None)
    access_mode_values = {choice[0] for choice in APIKey.ACCESS_MODE_CHOICES}

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip().lower()

        if action == "create":
            name = (request.POST.get("name") or "").strip()
            access_mode = (request.POST.get("access_mode") or APIKey.ACCESS_MODE_UNLIMITED).strip().lower()
            request_limit_raw = (request.POST.get("request_limit") or "").strip()
            request_limit = None

            if access_mode not in access_mode_values:
                messages.error(request, "Invalid API key mode.")
                return redirect("staff_api_keys")

            if access_mode == APIKey.ACCESS_MODE_LIMITED:
                try:
                    request_limit = int(request_limit_raw)
                except (TypeError, ValueError):
                    request_limit = 0
                if request_limit <= 0:
                    messages.error(request, "For limited keys, request limit must be a number greater than 0.")
                    return redirect("staff_api_keys")

            raw_key = APIKey.generate_raw_key()
            api_key = APIKey(
                name=name or "External API Key",
                access_mode=access_mode,
                request_limit=request_limit if access_mode == APIKey.ACCESS_MODE_LIMITED else None,
                is_active=True,
            )
            api_key.set_raw_key(raw_key)
            api_key.save()
            request.session["staff_api_generated_key"] = raw_key
            messages.success(request, f"API key '{api_key.name}' created.")
            return redirect("staff_api_keys")

        key_id = request.POST.get("key_id")
        api_key = APIKey.objects.filter(id=key_id).first()
        if not api_key:
            messages.error(request, "API key not found.")
            return redirect("staff_api_keys")

        if action == "regenerate":
            raw_key = APIKey.generate_raw_key()
            api_key.set_raw_key(raw_key)
            api_key.usage_count = 0
            api_key.save(update_fields=["key_hash", "key_prefix", "usage_count"])
            request.session["staff_api_generated_key"] = raw_key
            messages.success(request, f"API key '{api_key.name}' regenerated.")
            return redirect("staff_api_keys")

        if action == "activate":
            api_key.is_active = True
            api_key.save(update_fields=["is_active"])
            messages.success(request, f"API key '{api_key.name}' activated.")
            return redirect("staff_api_keys")

        if action == "deactivate":
            api_key.is_active = False
            api_key.save(update_fields=["is_active"])
            messages.success(request, f"API key '{api_key.name}' deactivated.")
            return redirect("staff_api_keys")

        if action == "reset_usage":
            api_key.usage_count = 0
            api_key.save(update_fields=["usage_count"])
            messages.success(request, f"Usage reset for API key '{api_key.name}'.")
            return redirect("staff_api_keys")

        messages.error(request, "Invalid action.")
        return redirect("staff_api_keys")

    keys = APIKey.objects.order_by("-created_at")
    return render(
        request,
        "staff_api_keys.html",
        {
            "api_keys": keys,
            "generated_key": generated_key,
            "access_modes": APIKey.ACCESS_MODE_CHOICES,
        },
    )


# -------------------------
# CHAT
# -------------------------

def chat_room(request):
    """Simple chat room: list messages and allow posting."""
    if not request.session.get("user_id"):
        messages.info(request, "Please log in to chat.")
        return redirect("login")

    ensure_chat_table()
    ensure_ping_table()
    lock = get_chat_lock()
    if lock.get("locked") and not request.user.is_staff:
        if not request.session.get("chat_unlocked"):
            return render(request, "chat_locked.html", {"locked": True})

    rows = query_all(
        """
        SELECT m.id,
               m.user_id,
               m.body,
               m.image_base64,
               m.reply_to_id,
               m.created_at,
               COALESCE(u.name, m.user_id) AS user_name,
               COALESCE(pu.name, p.user_id) AS parent_user_name,
               p.body AS parent_body
        FROM chat_messages m
        LEFT JOIN users u ON u.user_id = m.user_id
        LEFT JOIN chat_messages p ON p.id = m.reply_to_id
        LEFT JOIN users pu ON pu.user_id = p.user_id
        ORDER BY m.created_at ASC
        LIMIT 200
        """
    )
    return render(
        request,
        "chat.html",
        {
            "messages": rows,
            "chat_lock": lock,
        },
    )


@require_POST
def chat_send(request):
    """Post a new chat message."""
    user_id = request.session.get("user_id")
    if not user_id:
        return HttpResponseBadRequest("Not logged in.")

    ensure_chat_table()
    ensure_ping_table()
    lock = get_chat_lock()
    if lock.get("locked") and not request.user.is_staff and not request.session.get("chat_unlocked"):
        return HttpResponseBadRequest("Chat is locked.")
    body = (request.POST.get("body") or "").strip()
    reply_to_raw = (request.POST.get("reply_to_id") or "").strip()
    reply_to_id = None
    if reply_to_raw.isdigit():
        reply_to_id = int(reply_to_raw)
    image_file = request.FILES.get("image")
    image_b64 = None

    if not body and not image_file:
        messages.error(request, "Add a message or an image.")
        return redirect("chat_room")

    if body and len(body) > 1000:
        messages.error(request, "Message too long (max 1000 characters).")
        return redirect("chat_room")

    if image_file:
        # Limit to ~2MB
        if getattr(image_file, "size", 0) > 2 * 1024 * 1024:
            messages.error(request, "Image too large (max 2MB).")
            return redirect("chat_room")
        content = image_file.read()
        mime = image_file.content_type or "image/jpeg"
        encoded = base64.b64encode(content).decode("ascii")
        image_b64 = f"data:{mime};base64,{encoded}"

    execute(
        "INSERT INTO chat_messages (user_id, body, image_base64, reply_to_id) VALUES (%s, %s, %s, %s)",
        (user_id, body, image_b64, reply_to_id),
    )
    return redirect("chat_room")


@staff_member_required
@require_POST
def chat_delete(request, message_id: int):
    """Allow admins/staff to delete a message."""
    ensure_chat_table()
    execute("DELETE FROM chat_messages WHERE id = %s", (message_id,))
    messages.success(request, "Message deleted.")
    return redirect("chat_room")


@csrf_exempt
@require_POST
def chat_share_question(request):
    """Share a question image + optional note into community chat."""
    ensure_chat_table()
    ensure_ping_table()
    ensure_question_image_columns()
    lock = get_chat_lock()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to share."}, status=401)
    if lock.get("locked") and not request.user.is_staff and not request.session.get("chat_unlocked"):
        return JsonResponse({"error": "Chat is locked."}, status=403)

    try:
        if request.content_type and "application/json" in request.content_type:
            data = json.loads(request.body.decode("utf-8"))
        else:
            data = request.POST
    except Exception:
        data = {}

    question_id = (data.get("question_id") or "").strip()
    message_body = (data.get("message") or "").strip()

    if not question_id:
        return JsonResponse({"error": "question_id is required"}, status=400)

    if message_body and len(message_body) > 1000:
        return JsonResponse({"error": "Message too long (max 1000 characters)."}, status=400)

    question = query_one(
        "SELECT question_id, image_base64, image_url FROM questions WHERE question_id = %s",
        (question_id,),
    )
    if not question:
        return JsonResponse({"error": "Question not found."}, status=404)

    image_src = build_question_image_src(question.get("image_url"), question.get("image_base64"))
    body = message_body or f"Shared question {question_id}"

    execute(
        "INSERT INTO chat_messages (user_id, body, image_base64) VALUES (%s, %s, %s)",
        (user_id, body, image_src),
    )
    return JsonResponse({"status": "ok"})


@csrf_exempt
@require_POST
def chat_ping(request):
    """Ping another user; stores a ping and optional chat note."""
    ensure_chat_table()
    ensure_ping_table()
    lock = get_chat_lock()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in to ping."}, status=401)
    if lock.get("locked") and not request.user.is_staff and not request.session.get("chat_unlocked"):
        return JsonResponse({"error": "Chat is locked."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = request.POST

    target_user_id = (data.get("target_user_id") or "").strip()
    message_body = (data.get("message") or "").strip()

    if not target_user_id:
        return JsonResponse({"error": "target_user_id is required"}, status=400)
    if target_user_id == user_id:
        return JsonResponse({"error": "You cannot ping yourself."}, status=400)
    if message_body and len(message_body) > 200:
        return JsonResponse({"error": "Message too long (max 200 characters)."}, status=400)

    target = query_one("SELECT user_id, name FROM users WHERE user_id = %s", (target_user_id,))
    if not target:
        return JsonResponse({"error": "User not found"}, status=404)

    note = message_body or "You have been pinged."
    body = f"@{target.get('name') or target_user_id}: {note}"
    execute(
        "INSERT INTO chat_messages (user_id, body) VALUES (%s, %s)",
        (user_id, body),
    )
    chat_row = query_one("SELECT id FROM chat_messages WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
    chat_message_id = chat_row.get("id") if chat_row else None
    execute(
        "INSERT INTO chat_pings (target_user_id, from_user_id, message, chat_message_id) VALUES (%s, %s, %s, %s)",
        (target_user_id, user_id, note, chat_message_id),
    )
    return JsonResponse({"status": "ok"})


@csrf_exempt
def chat_pings(request):
    """Return unread pings for the current user; optional mark-as-read on POST."""
    ensure_ping_table()
    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"error": "Please log in"}, status=401)

    if request.method == "POST":
        execute(
            "UPDATE chat_pings SET read_at = NOW() WHERE target_user_id = %s AND read_at IS NULL",
            (user_id,),
        )
        return JsonResponse({"status": "ok"})

    rows = query_all(
        """
        SELECT p.id, p.from_user_id, p.message, p.chat_message_id, p.created_at,
               COALESCE(u.name, p.from_user_id) AS from_user_name
        FROM chat_pings p
        LEFT JOIN users u ON u.user_id = p.from_user_id
        WHERE p.target_user_id = %s AND p.read_at IS NULL
        ORDER BY p.created_at DESC
        LIMIT 20
        """,
        (user_id,),
    )
    return JsonResponse({"unread": len(rows), "pings": rows})


def chat_unlock(request):
    """Allow non-staff users to unlock chat with a password if locked."""
    ensure_chat_lock_table()
    lock = get_chat_lock()
    if not lock.get("locked"):
        request.session["chat_unlocked"] = True
        return redirect("chat_room")

    if request.method == "POST":
        supplied = (request.POST.get("password") or "").strip()
        if lock.get("password_hash") and check_password(supplied, lock["password_hash"]):
            request.session["chat_unlocked"] = True
            messages.success(request, "Chat unlocked.")
            return redirect("chat_room")
        messages.error(request, "Incorrect password. Please contact admin.")

    return render(request, "chat_locked.html", {"locked": True})


@staff_member_required
def chat_lock_admin(request):
    """Admin toggle to lock/unlock chat with a password."""
    ensure_chat_lock_table()
    lock = get_chat_lock()
    if request.method == "POST":
        locked = request.POST.get("locked") == "on"
        pwd = (request.POST.get("password") or "").strip()
        if locked and not pwd and not lock.get("password_hash"):
            messages.error(request, "Set a password before locking chat.")
            return redirect("chat_lock_admin")

        set_chat_lock(
            locked,
            pwd if locked and pwd else None,
            existing_hash=lock.get("password_hash") if locked and not pwd else None,
        )
        # Invalidate user unlock state
        request.session.pop("chat_unlocked", None)
        messages.success(request, "Chat lock updated.")
        return redirect("chat_lock_admin")

    return render(request, "staff_chat_lock.html", {"locked": lock.get("locked"), "has_password": bool(lock.get("password_hash"))})


# -------------------------
# LEGAL PAGES
# -------------------------

def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")


def disclaimer(request):
    return render(request, "disclaimer.html")
