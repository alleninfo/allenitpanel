from django.urls import path
from . import views

app_name = 'terminal'

urlpatterns = [
    path('', views.terminal, name='index'),
    path('start/', views.terminal_start, name='start'),
    path('stop/<str:terminal_id>/', views.terminal_stop, name='stop'),
    path('write/<str:terminal_id>/', views.terminal_write, name='write'),
    path('read/<str:terminal_id>/', views.terminal_read, name='read'),
    path('resize/<str:terminal_id>/', views.terminal_resize, name='resize'),
] 