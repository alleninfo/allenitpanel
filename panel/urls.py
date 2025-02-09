from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('apps/', views.app_store, name='app_store'),
    path('apps/<int:app_id>/install/', views.app_install, name='app_install'),
    path('apps/installation/<int:installation_id>/status/', views.app_install_status, name='app_install_status'),
] 