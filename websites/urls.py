from django.urls import path
from . import views

urlpatterns = [
    path('', views.website_list, name='website_list'),
    path('create/', views.website_create, name='website_create'),
    path('<int:pk>/edit/', views.website_edit, name='website_edit'),
    path('<int:pk>/delete/', views.website_delete, name='website_delete'),
    path('<int:pk>/toggle/', views.website_toggle, name='website_toggle'),
    path('<int:website_id>/domain/add/', views.domain_add, name='domain_add'),
    path('domain/<int:pk>/delete/', views.domain_delete, name='domain_delete'),
    path('websites/<int:pk>/mysql-status/', views.website_mysql_status, name='website_mysql_status'),
    path('website/<int:pk>/ssl/renew/', views.website_ssl_renew, name='website_ssl_renew'),
    path('website/<int:pk>/ssl/revoke/', views.website_ssl_revoke, name='website_ssl_revoke'),
    path('website/<int:pk>/ssl/apply/', views.website_ssl_apply, name='website_ssl_apply'),
    path('website/<int:pk>/ssl/upload/', views.website_ssl_upload, name='website_ssl_upload'),
    path('website/<int:pk>/ssl/dns-records/', views.website_ssl_dns_records, name='website_ssl_dns_records'),
]
