"""Supabase Storage helpers for question image uploads."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from django.conf import settings

_DATA_URI_RE = re.compile(r"^data:(?P<mime>[-\w.+]+/[-\w.+]+);base64,(?P<data>.+)$", re.IGNORECASE | re.DOTALL)
_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MIME_TO_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}


class StorageUploadError(RuntimeError):
    """Raised when storage configuration or upload fails."""


@dataclass(frozen=True)
class SupabaseStorageConfig:
    url: str
    service_role_key: str
    bucket: str
    public_base_url: str


def get_supabase_storage_config() -> SupabaseStorageConfig | None:
    """Return storage config from settings/env, or None if incomplete."""
    url = (getattr(settings, "SUPABASE_URL", None) or os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
    service_role_key = (
        getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", None)
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    ).strip()
    bucket = (
        getattr(settings, "SUPABASE_STORAGE_BUCKET", None)
        or os.getenv("SUPABASE_STORAGE_BUCKET")
        or ""
    ).strip()
    public_base_url = (
        getattr(settings, "SUPABASE_STORAGE_PUBLIC_BASE_URL", None)
        or os.getenv("SUPABASE_STORAGE_PUBLIC_BASE_URL")
        or ""
    ).strip().rstrip("/")

    if not (url and service_role_key and bucket):
        return None
    if not public_base_url:
        public_base_url = f"{url}/storage/v1/object/public/{urllib.parse.quote(bucket, safe='')}"

    return SupabaseStorageConfig(
        url=url,
        service_role_key=service_role_key,
        bucket=bucket,
        public_base_url=public_base_url,
    )


def is_supabase_storage_configured() -> bool:
    return get_supabase_storage_config() is not None


def _decode_base64_image(value: str) -> tuple[bytes, str | None]:
    text = (value or "").strip()
    if not text:
        raise StorageUploadError("Empty image payload.")

    mime_hint = None
    payload = text
    match = _DATA_URI_RE.match(text)
    if match:
        mime_hint = match.group("mime").lower()
        payload = match.group("data")

    cleaned = "".join(payload.split())
    if not cleaned:
        raise StorageUploadError("Image payload has no bytes.")

    try:
        binary = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        try:
            padding = "=" * (-len(cleaned) % 4)
            binary = base64.b64decode(cleaned + padding, validate=False)
        except Exception as exc:  # noqa: BLE001
            raise StorageUploadError(f"Invalid Base64 payload: {exc}") from exc

    if not binary:
        raise StorageUploadError("Decoded image payload is empty.")

    return binary, mime_hint


def _detect_content_type(content: bytes, mime_hint: str | None) -> str:
    if mime_hint in _MIME_TO_EXT:
        return mime_hint  # keep known explicit data-uri mime
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    return mime_hint or "application/octet-stream"


def _build_question_key(question_id: str, content: bytes, content_type: str) -> str:
    safe_qid = _SAFE_ID_RE.sub("-", (question_id or "").strip()) or "question"
    digest = hashlib.sha256(content).hexdigest()[:16]
    ext = _MIME_TO_EXT.get(content_type, "bin")
    return f"questions/{safe_qid}-{digest}.{ext}"


def _build_public_url(config: SupabaseStorageConfig, key: str) -> str:
    return f"{config.public_base_url}/{urllib.parse.quote(key, safe='/')}"


def _upload_binary(config: SupabaseStorageConfig, key: str, content: bytes, content_type: str) -> None:
    object_url = (
        f"{config.url}/storage/v1/object/"
        f"{urllib.parse.quote(config.bucket, safe='')}/"
        f"{urllib.parse.quote(key, safe='/')}"
    )
    req = urllib.request.Request(object_url, data=content, method="POST")
    req.add_header("Authorization", f"Bearer {config.service_role_key}")
    req.add_header("apikey", config.service_role_key)
    req.add_header("x-upsert", "true")
    req.add_header("Content-Type", content_type)
    req.add_header("Content-Length", str(len(content)))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            if resp.status >= 300:
                raise StorageUploadError(f"Upload failed with status {resp.status}.")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise StorageUploadError(f"Upload failed ({exc.code}): {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise StorageUploadError(f"Upload failed: {exc.reason}") from exc


def upload_question_base64(question_id: str, image_base64: str) -> dict:
    """Upload a question image payload and return `image_key` and `image_url`."""
    config = get_supabase_storage_config()
    if not config:
        raise StorageUploadError("Supabase storage is not configured.")

    content, mime_hint = _decode_base64_image(image_base64)
    content_type = _detect_content_type(content, mime_hint)
    key = _build_question_key(question_id, content, content_type)
    _upload_binary(config, key, content, content_type)
    return {
        "image_key": key,
        "image_url": _build_public_url(config, key),
        "content_type": content_type,
        "size_bytes": len(content),
    }
