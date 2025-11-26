"""Database helpers for PostgreSQL (Supabase)."""

import psycopg2
from psycopg2.extras import RealDictCursor
from django.conf import settings

# Lazily open a single connection so the app can start even if the DB is down.
_conn = None
_logged_reuse = False
_verbose_db_logs = bool(int(os.getenv("DB_VERBOSE", "0"))) if "os" in globals() else False


def get_conn():
    """Return a cached psycopg2 connection using Django settings."""
    global _conn
    global _logged_reuse
    if _conn and not _conn.closed:
        if _verbose_db_logs and not _logged_reuse:
            print("[db] Reusing existing DB connection")
            _logged_reuse = True
        return _conn

    cfg = settings.DATABASES["default"]
    timeout = getattr(settings, "DB_CONNECT_TIMEOUT", 5)
    host = cfg.get("HOST")
    user = cfg.get("USER")
    dbname = cfg.get("NAME")
    if _verbose_db_logs:
        print(f"[db] Opening DB connection to host={host} db={dbname} user={user} ssl={cfg.get('OPTIONS', {}).get('sslmode')}")
    try:
        _conn = psycopg2.connect(
            host=host,
            port=cfg.get("PORT"),
            dbname=dbname,
            user=user,
            password=cfg.get("PASSWORD"),
            sslmode=cfg.get("OPTIONS", {}).get("sslmode", "prefer"),
            connect_timeout=timeout,
        )
        _conn.autocommit = True
        if _verbose_db_logs:
            print("[db] Connection established.")
    except Exception as exc:
        print(f"[db] Connection failed: {exc}")
        raise
    return _conn


def query_all(sql: str, params: tuple = ()):
    """Return all rows for a query as a list of dictionaries."""
    with get_conn().cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql: str, params: tuple = ()):
    """Return a single row for a query as a dictionary."""
    with get_conn().cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql: str, params: tuple = ()):
    """Execute a statement that does not return rows."""
    with get_conn().cursor() as cur:
        cur.execute(sql, params)


def get_or_create_activity(user_id: str, question_id: str) -> dict:
    """Fetch a user/question activity record or create a default one."""
    doc = query_one(
        "SELECT * FROM user_activity WHERE user_id = %s AND question_id = %s",
        (user_id, question_id),
    )
    if doc:
        return doc

    execute(
        """
        INSERT INTO user_activity (
            user_id, question_id, solved, correct, bookmarked, starred,
            times_viewed, time_started, time_took
        ) VALUES (%s, %s, false, false, false, false, 0, NULL, NULL)
        """,
        (user_id, question_id),
    )
    return query_one(
        "SELECT * FROM user_activity WHERE user_id = %s AND question_id = %s",
        (user_id, question_id),
    )


def get_next_user_id() -> str:
    """Generate a simple incremental user_id like U1, U2, ..."""
    last = query_one("SELECT user_id FROM users ORDER BY user_id DESC LIMIT 1")
    if last and "user_id" in last:
        try:
            last_num = int(str(last["user_id"])[1:])
            return f"U{last_num + 1}"
        except (ValueError, TypeError):
            pass
    return "U1"
