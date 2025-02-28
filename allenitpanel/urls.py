from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('websites.urls')),
    path('ws/', include('websites.routing')),  # 添加 WebSocket 路由
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) 