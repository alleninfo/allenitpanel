from django.urls import path
from . import views

app_name = 'terminal'

urlpatterns = [
    path('', views.terminal, name='index'),
    path('execute/', views.execute_command, name='execute'),
] 