from django.conf import settings
from django.utils.deprecation import MiddlewareMixin


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
