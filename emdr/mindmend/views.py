import random
from datetime import datetime, timedelta
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from .serializers import UserSignupSerializer
from .models import CustomUser
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


class UserSignupViewSet(viewsets.ModelViewSet):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    serializer_class = UserSignupSerializer
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {"message": "User created successfully.", "data": serializer.data},
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    def perform_create(self, serializer):
        serializer.save()


class GetTokenViewSet(viewsets.ViewSet):
    @swagger_auto_schema(
        operation_description="Get JWT token for a user",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User email"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User password"
                ),
            },
        ),
        responses={200: "Token retrieved successfully"},
    )
    def create(self, request):
        email = request.data.get("email", None)
        password = request.data.get("password", None)
        if not email:
            return Response(
                {"message": "Kindly fill email's field", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not password:
            return Response(
                {"message": "Kindly fill password's field", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = CustomUser.objects.filter(email=email).first()
        if user and user.check_password(password):
            user = authenticate(request, username=user.username, password=password)
            login(request, user)
            expiration_time = datetime.now() + timedelta(minutes=60)
            refresh_expiration_time = datetime.now() + timedelta(minutes=60)
            token = RefreshToken.for_user(user)
            data = {
                "refresh_token": str(token),
                "access_token": str(token.access_token),
                "refresh_token_expiry": refresh_expiration_time,
                "access_token_expiry": expiration_time,
                "id": user.id,
            }
            return Response(
                {"message": "Logged in successfully", "data": data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": "Invalid username or password.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasswordResetViewSet(viewsets.ViewSet):
    @swagger_auto_schema(
        operation_description="Send OTP to user email for password reset",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, description="User email"),
            },
            required=["email"]
        ),
        responses={200: "OTP sent successfully"},
    )
    @action(detail=False, methods=["post"], url_path="send-otp")
    def send_otp(self, request):
        email = request.data.get("email", None)

        if not email:
            return Response({"msg": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response({"msg": "Email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate and save OTP
        while True:
            code = random.randint(1000, 9999)
            if not CustomUser.objects.filter(otp_check=code).exists():
                break
        user.otp_check = code
        user.save()

        # Send OTP email
        text_content = "This is an important message."
        htmly = get_template("forget_password.html")
        d = {"otp": code}
        html_content = htmly.render(d)
        msg = EmailMultiAlternatives(
            "OTP for EzyUsers", text_content, settings.EMAIL_HOST_USER, [user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        return Response({"msg": "OTP sent to email"}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="Verify OTP for password reset",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, description="User email"),
                "otp": openapi.Schema(type=openapi.TYPE_STRING, description="OTP code"),
            },
            required=["email", "otp"]
        ),
        responses={200: "OTP verified successfully"},
    )
    @action(detail=False, methods=["post"], url_path="verify-otp")
    def verify_otp(self, request):
        email = request.data.get("email", None)
        otp = request.data.get("otp", None)

        if not email or not otp:
            return Response({"msg": "Email and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()
        if not user or user.otp_check != int(otp):
            return Response({"msg": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"msg": "OTP verified, you can now reset your password"}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="Set new password after OTP verification",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, description="User email"),
                "otp": openapi.Schema(type=openapi.TYPE_STRING, description="OTP code"),
                "new_password": openapi.Schema(type=openapi.TYPE_STRING, description="New password"),
            },
            required=["email", "otp", "new_password"]
        ),
        responses={200: "Password reset successfully"},
    )
    @action(detail=False, methods=["post"], url_path="set-password")
    def set_password(self, request):
        email = request.data.get("email", None)
        otp = request.data.get("otp", None)
        new_password = request.data.get("new_password", None)

        if not email or not otp or not new_password:
            return Response({"msg": "Email, OTP, and new password are required"}, status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 8:
            return Response({"msg": "Password length should be greater or equal to 8"}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()
        if not user or user.otp_check != int(otp):
            return Response({"msg": "Invalid OTP or user not found"}, status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.otp_check = 0
        user.save()

        return Response({"msg": "Password reset successfully"}, status=status.HTTP_200_OK)


class UserLogoutViewSet(viewsets.ViewSet):
    @method_decorator(csrf_exempt)
    @swagger_auto_schema(
        operation_description="Logout user by blacklisting the refresh token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh_token": openapi.Schema(type=openapi.TYPE_STRING, description="Refresh token"),
            },
            required=["refresh_token"]
        ),
        responses={200: "User logged out successfully"},
    )
    def logout(self, request):
        refresh_token = request.data.get("refresh_token", None)

        if not refresh_token:
            return Response({"msg": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"msg": "User logged out successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"msg": "Invalid token or token has already been blacklisted"}, status=status.HTTP_400_BAD_REQUEST)