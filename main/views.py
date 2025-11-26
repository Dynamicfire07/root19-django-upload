from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.admin.views.decorators import staff_member_required
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import random
import json

from .db import (
    query_one,
    query_all,
    execute,
    get_next_user_id,
    get_or_create_activity,
)
from .models import BugReport


# -------------------------
# AUTHENTICATION
# -------------------------

def register(request):
    """Handle user registration."""
    if request.method == 'POST':
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
            INSERT INTO users (user_id, name, email, password, role, school)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                get_next_user_id(),
                name,
                email,
                hashed_password,
                role,
                school,
            ),
        )
        messages.success(request, "Registration successful! Please log in.")
        return redirect('login')

    return render(request, 'register.html')


def login_view(request):
    """Handle login using the users table."""
    if request.method == 'POST':
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

# -------------------------
# MAIN PAGES
# -------------------------

def home(request):
    """Render the home page with the question count."""
    total_questions = query_one("SELECT COUNT(*) AS cnt FROM questions")['cnt']
    return render(request, 'home.html', {'total_questions': total_questions})


def question_bank(request):
    """Render the initial page with session codes."""
    rows = query_all("SELECT DISTINCT session_code FROM questions")
    session_codes = [r['session_code'] for r in rows]
    return render(request, 'question_bank.html', {'session_codes': session_codes})


def get_subtopics(request):
    """Return subtopics for a given session code."""
    session_code = request.GET.get('session_code')
    if not session_code:
        return JsonResponse({'error': 'Session code is required'}, status=400)

    rows = query_all(
        "SELECT DISTINCT subtopic FROM questions WHERE session_code = %s",
        (session_code,),
    )
    subtopics = [r['subtopic'] for r in rows]
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
    questions = [SimpleNamespace(**doc) for doc in docs]

    # ✅ Safely get user_id from session
    user_id = request.session.get('user_id')
    if not user_id:
        # fallback (guest mode) if someone isn’t logged in
        user_id = None

    return render(request, 'practice_questions.html', {
        'questions': questions,
        'user_id': user_id,
        'limit': None if user_id else 2,
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

    totals = query_one(
        "SELECT COUNT(*) AS attempts FROM user_activity WHERE user_id = %s",
        (user_id,),
    ) or {"attempts": 0}
    solved = query_one(
        "SELECT COUNT(*) AS solved FROM user_activity WHERE user_id = %s AND solved = TRUE",
        (user_id,),
    ) or {"solved": 0}
    correct = query_one(
        "SELECT COUNT(*) AS correct FROM user_activity WHERE user_id = %s AND correct = TRUE",
        (user_id,),
    ) or {"correct": 0}
    bookmarked = query_one(
        "SELECT COUNT(*) AS bookmarked FROM user_activity WHERE user_id = %s AND bookmarked = TRUE",
        (user_id,),
    ) or {"bookmarked": 0}
    starred = query_one(
        "SELECT COUNT(*) AS starred FROM user_activity WHERE user_id = %s AND starred = TRUE",
        (user_id,),
    ) or {"starred": 0}
    avg_time_row = query_one(
        "SELECT AVG(time_took) AS avg_time FROM user_activity WHERE user_id = %s AND time_took IS NOT NULL",
        (user_id,),
    ) or {"avg_time": None}

    attempts = totals.get("attempts", 0) or 0
    solved_count = solved.get("solved", 0) or 0
    correct_count = correct.get("correct", 0) or 0
    accuracy = round((correct_count / solved_count) * 100, 1) if solved_count else 0.0

    avg_time_val = avg_time_row.get("avg_time")
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

    context = {
        "user": user,
        "stats": {
            "attempts": attempts,
            "solved": solved_count,
            "correct": correct_count,
            "accuracy": accuracy,
            "bookmarked": bookmarked.get("bookmarked", 0) or 0,
            "starred": starred.get("starred", 0) or 0,
            "avg_time": avg_time_display,
        },
        "recent": recent,
        "by_topic": by_topic,
        "leaderboard": leaderboard,
        "bookmarked_rows": bookmarked_rows,
        "starred_rows": starred_rows,
        "saved": saved,
    }
    return render(request, "user_stats.html", context)


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
    records = [SimpleNamespace(**row) for row in query_all("SELECT * FROM user_activity")]

    summary = {
        "total_users": query_one("SELECT COUNT(*) AS cnt FROM users")['cnt'],
        "total_questions": query_one("SELECT COUNT(*) AS cnt FROM questions")['cnt'],
        "total_records": query_one("SELECT COUNT(*) AS cnt FROM user_activity")['cnt'],
        "solved": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE solved = TRUE")['cnt'],
        "correct": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE correct = TRUE")['cnt'],
        "starred": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE starred = TRUE")['cnt'],
        "bookmarked": query_one("SELECT COUNT(*) AS cnt FROM user_activity WHERE bookmarked = TRUE")['cnt'],
    }

    return render(request, "user_activity_admin.html", {"records": records, "summary": summary})


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


# -------------------------
# LEGAL PAGES
# -------------------------

def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")


def disclaimer(request):
    return render(request, "disclaimer.html")
