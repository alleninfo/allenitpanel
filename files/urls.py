from django.urls import path
from . import views

urlpatterns = [
    path('', views.file_manager, name='file_manager'),
    path('browse/', views.file_browse, name='file_browse'),
    path('upload/', views.file_upload, name='file_upload'),
    path('download/', views.file_download, name='file_download'),
    path('create_folder/', views.create_folder, name='create_folder'),
    path('rename/', views.file_rename, name='file_rename'),
    path('delete/', views.file_delete, name='file_delete'),
    path('share/', views.file_share, name='file_share'),
    path('share/<str:token>/', views.file_share_download, name='file_share_download'),
    path('paste/', views.paste_files, name='paste_files'),
    path('batch-delete/', views.batch_delete, name='batch_delete'),
    path('compress/', views.compress_files, name='compress_files'),
    path('remote-download/', views.remote_download, name='remote_download'),
    path('edit/', views.file_edit, name='file_edit'),
    path('edit/save/', views.file_edit_save, name='file_edit_save'),
] 