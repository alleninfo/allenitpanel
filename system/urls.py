from django.urls import path
from . import views

urlpatterns = [
    # 系统状态
    path('status/', views.system_status, name='system_status'),
    path('stats/', views.system_stats, name='system_stats'),
    
    # 进程管理
    path('process/<int:pid>/kill/', views.kill_process_view, name='kill_process'),
    
    # 服务管理
    path('service/<int:service_id>/control/', views.service_control, name='service_control'),
    
    # 系统日志
    path('logs/', views.system_logs_view, name='system_logs'),
    
    # 系统更新
    path('updates/', views.system_updates_view, name='system_updates'),
    path('updates/package/', views.update_package, name='update_package'),
    path('updates/all/', views.update_all, name='update_all'),
    
    # 网络连接
    path('network/', views.network_connections, name='network_connections'),
    
    # 系统状态快照
    path('status/save/', views.save_system_status, name='save_system_status'),
] 