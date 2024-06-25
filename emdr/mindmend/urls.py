from django.urls import path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from .views import GetTokenViewSet, PasswordResetViewSet, UserSignupViewSet, UserLogoutViewSet

schema_view = get_schema_view(
    openapi.Info(
        title="Your API",
        default_version="v1",
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@local.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# Instantiate your viewsets
get_token = GetTokenViewSet.as_view({"post": "create"})
user_signup = UserSignupViewSet.as_view({"post": "create"})
send_otp = PasswordResetViewSet.as_view({"post": "send_otp"})
verify_otp = PasswordResetViewSet.as_view({"post": "verify_otp"})
set_password = PasswordResetViewSet.as_view({"post": "set_password"})
logout = UserLogoutViewSet.as_view({"post": "logout"})

urlpatterns = [
    re_path(
        r"^swagger(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
    path("login/", get_token, name="login"),
    path("signup/", user_signup, name="user_signup"),
    path("password-reset/send-otp/", send_otp, name="send_otp"),
    path("password-reset/verify-otp/", verify_otp, name="verify_otp"),
    path("password-reset/set-password/", set_password, name="set_password"),
    path("logout/", logout, name="logout"),
]
