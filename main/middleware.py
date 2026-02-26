import logging
import time

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

request_logger = logging.getLogger("main.request_actions")


def _is_static_or_media(path: str) -> bool:
    static_url = getattr(settings, "STATIC_URL", "/static/")
    media_url = getattr(settings, "MEDIA_URL", "/media/")
    return bool((static_url and path.startswith(static_url)) or (media_url and path.startswith(media_url)))


def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


class RequestActionLoggingMiddleware(MiddlewareMixin):
    """
    Log request/response actions to help diagnose production issues.
    """

    def process_request(self, request):
        request._request_started_at = time.monotonic()
        return None

    def process_exception(self, request, exception):
        path = getattr(request, "path", "")
        if _is_static_or_media(path):
            return None
        user_id = getattr(getattr(request, "session", {}), "get", lambda *args, **kwargs: None)("user_id")
        request_logger.exception(
            "unhandled_exception method=%s path=%s user_id=%s ip=%s error=%s",
            getattr(request, "method", ""),
            path,
            user_id or "-",
            _client_ip(request) or "-",
            exception.__class__.__name__,
        )
        return None

    def process_response(self, request, response):
        path = getattr(request, "path", "")
        if _is_static_or_media(path):
            return response

        started_at = getattr(request, "_request_started_at", None)
        duration_ms = int((time.monotonic() - started_at) * 1000) if started_at is not None else -1

        user_id = "-"
        session = getattr(request, "session", None)
        if session is not None:
            try:
                user_id = session.get("user_id") or "-"
            except Exception:
                user_id = "-"

        status = getattr(response, "status_code", 0)
        log_fn = request_logger.info
        if status >= 500:
            log_fn = request_logger.error
        elif status >= 400:
            log_fn = request_logger.warning

        log_fn(
            "request_action method=%s path=%s status=%s duration_ms=%s user_id=%s ip=%s",
            getattr(request, "method", ""),
            path,
            status,
            duration_ms,
            user_id,
            _client_ip(request) or "-",
        )
        return response


class StaticMediaCacheMiddleware(MiddlewareMixin):
    """
    Add long-lived cache headers for static/media assets when served by Django.
    This should be paired with hashed filenames in production or a CDN fronting static/media.
    """

    def process_response(self, request, response):
        path = request.path
        if request.method in ("GET", "HEAD"):
            static_url = getattr(settings, "STATIC_URL", "/static/")
            media_url = getattr(settings, "MEDIA_URL", "/media/")
            if (static_url and path.startswith(static_url)) or (media_url and path.startswith(media_url)):
                if response.status_code == 200:
                    # One year; immutable for hashed assets
                    response["Cache-Control"] = "public, max-age=31536000, immutable"
        return response
