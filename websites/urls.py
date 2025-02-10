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
]
