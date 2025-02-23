from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('website_manage/', views.website_manage, name='website_manage'),
    path('database_manage/', views.database_manage, name='database_manage'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('firewall_manage/', views.firewall_manage, name='firewall_manage'),
    path('file_manage/', views.file_manage, name='file_manage'),
    path('terminal_manage/', views.terminal_manage, name='terminal_manage'),
    path('cron_manage/', views.cron_manage, name='cron_manage'),
    path('app_store/', views.app_store, name='app_store'),
    path('app_store/install/<int:app_id>/', views.install_app, name='install_app'),
    path('app_store/uninstall/<int:app_id>/', views.uninstall_app, name='uninstall_app'),
    path('app_store/logs/<int:app_id>/', views.get_install_logs, name='app_install_logs'),
    path('app_store/search/', views.search_apps, name='search_apps'),
    path('api/service/<str:service>/<str:action>/', views.control_service, name='control_service'),
    path('website_list/', views.website_list, name='website_list'),
    path('add/', views.add_website, name='add_website'),
    path('<int:id>/restart/', views.restart_website, name='restart_website'),
    path('<int:id>/delete/', views.delete_website, name='delete_website'),
    path('api/system-info/', views.system_info_api, name='system_info_api'),
]