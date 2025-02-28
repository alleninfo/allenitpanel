from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('terminal/<str:session_id>/', consumers.TerminalConsumer.as_asgi()),
] 