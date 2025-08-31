"""Database helpers for PostgreSQL (Supabase)."""

import psycopg2
from psycopg2.extras import RealDictCursor
from django.conf import settings

# Establish a global connection to the Supabase (PostgreSQL) database. The
# credentials are currently hard-coded in ``settings.py``.
conn = psycopg2.connect(
    host="aws-1-ap-south-1.pooler.supabase.com",
    port=6543,
    dbname="postgres",
    user="postgres.vzmbwobdlddxzgqfhnsh",
    password="shaishavroot19",
    sslmode="require"
)
conn.autocommit = True


def query_all(sql: str, params: tuple = ()):
    """Return all rows for a query as a list of dictionaries."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql: str, params: tuple = ()):
    """Return a single row for a query as a dictionary."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql: str, params: tuple = ()):
    """Execute a statement that does not return rows."""
    with conn.cursor() as cur:
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

