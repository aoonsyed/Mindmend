import random
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import logout, authenticate, login
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import CustomUserSerializer, UserSignupSerializer, ContactMessageSerializer, \
    UserProfileUpdateSerializer, ScoresSerializer, ScoreRecordSerializer
from .models import CustomUser, Contact, Scores, Emotion, ScoreRecord
from django.conf import settings


@method_decorator(csrf_exempt, name='dispatch')
class UserSignupViewSet(viewsets.ModelViewSet):
    serializer_class = UserSignupSerializer
    queryset = CustomUser.objects.all()
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        """
        Create a new user.

        Example JSON:
        {
            "username": "john_doe",
            "email": "john.doe@example.com",
            "password": "securepassword123"
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(
            {"message": "User created successfully.", "data": serializer.data},
            status=status.HTTP_201_CREATED,
        )

    def perform_create(self, serializer):
        serializer.save()


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        User login API

        Example JSON Request:
        {
            "email": "john.doe@example.com",
            "password": "securepassword123"
        }

        Example JSON Response (Success):
        {
            "message": "Logged in successfully.",
            "refresh_token": "<refresh_token>",
            "access_token": "<access_token>",
            "email": "john.doe@example.com"
        }

        Example JSON Response (Failure):
        {
            "message": "Invalid email or password. Please check your credentials and try again."
        }
        """
        email = request.data.get("email", None)
        password = request.data.get("password", None)

        if not email or not password:
            return Response(
                {"message": "Both email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        get_user = CustomUser.objects.filter(email=email).first()
        if not get_user:
            return Response(
                {"message": "User not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user = authenticate(request, username=get_user.username, password=password)

        if user:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            data = {
                "refresh_token": str(refresh),
                "access_token": str(refresh.access_token),
                "email": email,
                "user_id": user.id,
            }
            return Response(
                {
                    "data": data,
                    "message": "Logged in successfully.",

                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "message": "Invalid email or password. Please check your credentials and try again.",
                    "data": {}
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserLogoutViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def logout(self, request):
        """
        Logout user.

        Example JSON:
        {
            "refresh_token": "<refresh_token>"
        }

        Example Response JSON:
        {
            "message": "User logged out successfully."
        }
        """
        refresh_token = request.data.get("refresh_token", None)

        if not refresh_token:
            return Response(
                {"message": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return Response(
                {"message": "User logged out successfully."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"message": "Invalid token or token has already been blacklisted."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # User = get_user_model()

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response({'message': 'User with this email does not exist.'},
                            status=status.HTTP_404_NOT_FOUND)

        # uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        # print(uidb64)
        while True:
            code = random.randint(1000000, 9999999)
            if not CustomUser.objects.filter(uid=code).exists():
                break
        user.uid = code
        user.save()
        reset_url = f"http://adminmend.pythonanywhere.com/mindmend/reset-password/confirm/?uid={code}"

        text_content = "This is an important message."
        htmly = get_template("forget_password.html")
        d = {"otp": reset_url}
        html_content = htmly.render(d)
        msg = EmailMultiAlternatives(
            "Password Reset Link", text_content, settings.EMAIL_HOST_USER, [user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        return Response({
            'message': 'Password reset link has been sent to your email.',
        }, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        uid = request.data.get('UID')  # Changed from query_params to data
        new_password = request.data.get('new_password')
        email = request.data.get('email')

        if not uid or not new_password or not email:
            return Response(
                {"message": "UID, new password, and email are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response({'message': 'User with this email does not exist.'},
                            status=status.HTTP_404_NOT_FOUND)

        try:
            if str(user.uid) != uid:
                raise ValueError("UID does not match")
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist) as e:
            return Response(
                {"message": "The reset link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.uid = None  # Invalidate the UID after password reset
        user.save()
        data = {
            "email": email,
            "user_id": user.id,
        }
        return Response({
            "data": data,
            'message': 'Password has been reset successfully.'},
            status=status.HTTP_200_OK)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import ContactMessageSerializer
from .models import Contact


class ContactUsAPIView(APIView):
    def post(self, request, format=None):
        serializer = ContactMessageSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            # Check if the email already exists
            if Contact.objects.filter(email=email).exists():
                return Response({'message': 'Email already exists in database.'}, status=status.HTTP_409_CONFLICT)

            # Save the serializer instance
            contact_instance = serializer.save()

            # Prepare data for response
            data = {
                'email': email,
                'message': serializer.validated_data['message'],  # Retrieve the message from validated data
                'contact_id': contact_instance.id,  # Assuming you want to send the ID of the Contact instance
            }

            return Response({'data': data, 'message': 'Message sent successfully.'}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserListAPIView(APIView):
    def get(self, request, format=None):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def put(self, request, *args, **kwargs):
        serializer = UserProfileUpdateSerializer(request.user, data=request.data, partial=True,
                                                 context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class UserTherapyInfoAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Create or update therapy info for the authenticated user.
        """
        request_data = request.data.copy()
        request_data['user'] = request.user.id


        scores = Scores.objects.filter(user=request.user).first()
        if scores:
            serializer = ScoresSerializer(scores, data=request_data, partial=True)
        else:
            serializer = ScoresSerializer(data=request_data)

        if serializer.is_valid():
            serializer.save(user=request.user)  # Ensure the user is saved
            return Response({
                'message': 'Therapy info created/updated successfully.',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'message': 'Failed to create/update therapy info.',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class UserScoreRecordsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        List all score records for the authenticated user.
        """
        user = request.user
        score_records = ScoreRecord.objects.filter(user=user)
        serializer = ScoreRecordSerializer(score_records, many=True)
        return Response({
            'message': 'Score records retrieved successfully.',
            'data': serializer.data
        }, status=status.HTTP_200_OK)




