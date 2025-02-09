from django.urls import path
from . import views

urlpatterns = [
    path('', views.database_list, name='database_list'),
    path('create/', views.database_create, name='database_create'),
    path('<int:pk>/', views.database_detail, name='database_detail'),
    path('<int:pk>/backup/', views.database_backup, name='database_backup'),
    path('<int:pk>/restore/', views.database_restore, name='database_restore'),
    path('<int:pk>/delete/', views.database_delete, name='database_delete'),
    path('<int:pk>/users/', views.database_users, name='database_users'),
    path('<int:pk>/users/add/', views.database_user_add, name='database_user_add'),
    path('<int:pk>/users/<int:user_pk>/delete/', views.database_user_delete, name='database_user_delete'),
    path('<int:pk>/backup/schedule/', views.database_backup_schedule, name='database_backup_schedule'),
    path('<int:pk>/backup/schedule/save/', views.save_backup_schedule, name='database_backup_schedule_save'),
    path('<int:pk>/backup/schedule/<int:schedule_id>/', views.get_backup_schedule, name='database_backup_schedule_detail'),
    path('<int:pk>/backup/schedule/<int:schedule_id>/toggle/', views.toggle_backup_schedule, name='database_backup_schedule_toggle'),
    path('<int:pk>/backup/schedule/<int:schedule_id>/delete/', views.delete_backup_schedule, name='database_backup_schedule_delete'),
    path('<int:pk>/backup/settings/', views.database_backup_settings, name='database_backup_settings'),
    path('<int:pk>/export/', views.database_export, name='database_export'),
    path('<int:pk>/export/<int:export_id>/delete/', views.delete_export, name='delete_export'),
    path('<int:pk>/import/', views.database_import, name='database_import'),
    path('<int:pk>/import/<int:import_id>/delete/', views.delete_import, name='delete_import'),
] 