from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    LoginView,
    PasswordResetView,
    PasswordResetConfirmView,
    ContactUsAPIView,
    UserListAPIView,
    UserProfileUpdateAPIView,
    UserTherapyInfoAPIView,
    UserSignupViewSet,
    UserLogoutViewSet,
    UserScoreRecordsViewSet,
)

# Instantiate your viewsets
signup = UserSignupViewSet.as_view({"post": "create"})
logout = UserLogoutViewSet.as_view({"post": "logout"})

router = DefaultRouter()
router.register(r'score-records', UserScoreRecordsViewSet, basename='score-records')

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', signup, name='signup'),
    path('reset-password/', PasswordResetView.as_view(), name='password_reset'),
    path('reset-password/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('logout/', logout, name='logout'),
    path('contact-us/', ContactUsAPIView.as_view(), name='contact_us'),
    path('users/', UserListAPIView.as_view(), name='user_list'),
    path('profile/update/', UserProfileUpdateAPIView.as_view(), name='profile_update'),
    path('user_therapy_info/', UserTherapyInfoAPIView.as_view(), name='user_therapy_info'),
    path('', include(router.urls)),
]
