from django.urls import re_path

from main import routing as main_routing

websocket_urlpatterns = [
    *main_routing.websocket_urlpatterns,
]
