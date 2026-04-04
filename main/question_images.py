"""Helpers for migrating question images from Base64 blobs to URL storage."""

from __future__ import annotations

from .db import execute
from .supabase_storage import build_public_url_from_key

_question_image_columns_ready = False


def ensure_question_image_columns() -> None:
    """Ensure URL-based image columns exist on questions."""
    global _question_image_columns_ready
    if _question_image_columns_ready:
        return
    execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS image_key TEXT;")
    execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS image_url TEXT;")
    execute("CREATE INDEX IF NOT EXISTS idx_questions_image_key ON questions (image_key);")
    _question_image_columns_ready = True


def build_question_image_src(
    image_url: str | None,
    image_base64: str | None,
    image_key: str | None = None,
) -> str | None:
    """Prefer stored URLs/keys, otherwise normalize Base64 into a browser-ready src string."""
    url_val = (image_url or "").strip()
    if url_val:
        return url_val

    key_url = build_public_url_from_key(image_key or "")
    if key_url:
        return key_url

    b64_val = (image_base64 or "").strip()
    if not b64_val:
        return None
    if b64_val.startswith(("data:", "http://", "https://")):
        return b64_val
    return f"data:image/png;base64,{b64_val}"


def apply_question_image_src(row: dict) -> dict:
    """Attach `image_src` key to a question row dictionary."""
    row["image_src"] = build_question_image_src(
        row.get("image_url"),
        row.get("image_base64"),
        row.get("image_key"),
    )
    return row


def apply_question_image_src_to_rows(rows: list[dict]) -> list[dict]:
    """Attach `image_src` to each row in-place."""
    for row in rows:
        apply_question_image_src(row)
    return rows
