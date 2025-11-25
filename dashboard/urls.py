# dashboard/urls.py
from django.urls import path
from . import views
app_name = 'dashboard'  # This defines the namespace

urlpatterns = [
    path('', views.dashboard_home, name='dashboard_home'),
    path('users/', views.user_list, name='user_list'),
    path('subscriptions/', views.subscription_list, name='subscription_list'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),

]
 