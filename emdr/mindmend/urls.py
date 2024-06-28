from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import LoginView, UserSignupViewSet, UserLogoutViewSet
from . import views
# Instantiate your viewsets
signup = UserSignupViewSet.as_view({"post": "create"})
logout = UserLogoutViewSet.as_view({"post": "logout"})

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', signup, name='signup'),
    path('reset-password/', views.PasswordResetView.as_view(), name='password_reset'),
    path('reset-password/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('logout/', logout, name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
