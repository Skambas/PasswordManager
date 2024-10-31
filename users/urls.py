from django.urls import path
from .views import RegisterView, LoginView, LogoutView, VaultView, GetSaltView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('vault/', VaultView.as_view(), name='vault'),
    path('get_salt/', GetSaltView.as_view(), name='get_salt'),
]
