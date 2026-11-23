from django.urls import path
from . import views

urlpatterns = [
    path('registro/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('recuperar-password/', views.password_reset_request_view, name='password_reset_request'),
    path('restablecer-password/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('', views.home_view, name='home'),
]