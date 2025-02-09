from django.urls import path
from . import views

urlpatterns = [
    path('', views.website_list, name='website_list'),
    path('create/', views.website_create, name='website_create'),
    path('<int:pk>/', views.website_detail, name='website_detail'),
    path('<int:pk>/toggle/', views.website_toggle, name='website_toggle'),
    path('<int:pk>/delete/', views.website_delete, name='website_delete'),
    path('<int:pk>/ssl/', views.website_ssl, name='website_ssl'),
    path('<int:pk>/config/', views.website_config, name='website_config'),
    path('<int:pk>/logs/', views.website_logs, name='website_logs'),
] 