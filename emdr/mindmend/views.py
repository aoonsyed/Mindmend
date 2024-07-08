import random
from django.utils import timezone
from io import BytesIO
from PIL import Image, UnidentifiedImageError
from django.contrib.auth.tokens import default_token_generator
from django.core.files.base import ContentFile
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import logout, authenticate, login
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status, generics
from rest_framework.decorators import api_view, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import CustomUserSerializer, UserSignupSerializer, ContactMessageSerializer, \
    UserProfileUpdateSerializer, ScoresSerializer, ScoreRecordSerializer, SubscriptionCreateSerializer, \
    SubscriptionSerializer, SubscriptionDetailSerializer
from .models import CustomUser, Contact, Scores, Emotion, ScoreRecord, Subscription
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Constants
FREE_SUBSCRIPTION = "free"
SUBSCRIPTION_PLANS = [
    {"name": "Free", "description": "Free", "amount": 0, "duration": "14 Days"},
    {"name": "Monthly", "description": "Full Customisation and Tracking.", "amount": 4.00, "duration": "1 month"},
    {"name": "Yearly", "description": "Full Customisation and Tracking.", "amount": 29.99, "duration": "12 months"},
]
RANDOM_CODE_MIN = 1000000
RANDOM_CODE_MAX = 9999999


@method_decorator(csrf_exempt, name='dispatch')
class UserSignupViewSet(viewsets.ModelViewSet):
    """
    User Signup ViewSet
    """
    queryset = CustomUser.objects.all()
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        """
        Handle user signup
        """
        try:
            name = request.data.get('name')
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return self._response(
                    {"message": "Both email and password are required.", "data": {}},
                    status.HTTP_400_BAD_REQUEST,
                )

            if CustomUser.objects.filter(email=email).exists():
                return self._response(
                    {"message": "User with this email already exists.", "data": {}},
                    status.HTTP_400_BAD_REQUEST,
                )

            user = CustomUser.objects.create_user(name=name, email=email, password=password)
            user.save()

            return self._response(
                {"message": "User created successfully.",
                 "data": {"id": user.id, "name": user.name, "email": user.email}},
                status.HTTP_201_CREATED,
            )
        except Exception as e:
            return self._response(
                {"message": f"Error: {str(e)}", "data": {}},
                status.HTTP_400_BAD_REQUEST
            )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class SubscriptionListView(APIView):
    """
    List of subscription plans
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        """
        Retrieve subscription plans
        """
        try:
            return self._response(
                {"message": "Subscription plans retrieved successfully.", "data": SUBSCRIPTION_PLANS},
                status.HTTP_200_OK
            )
        except Exception as e:
            return self._response(
                {"message": f"Error: {str(e)}", "data": {}},
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class SubscriptionCreateView(generics.CreateAPIView):
    """
    Create a new subscription
    """
    serializer_class = SubscriptionCreateSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        """
        Handle subscription creation
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return self._response(
                {"message": "Subscription created successfully.", "data": serializer.data},
                status.HTTP_201_CREATED,
                headers
            )
        except Exception as e:
            return self._response(
                {"message": "Not a valid subscription", "data": serializer.errors if 'serializer' in locals() else {}},
                status.HTTP_400_BAD_REQUEST
            )

    def perform_create(self, serializer):
        """
        Associate the subscription with the authenticated user
        """
        serializer.save(user=self.request.user)

    def _response(self, message_data, status_code, headers=None):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code, headers=headers)


class LoginView(APIView):
    """
    Handle user login
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Authenticate and login user
        """
        email = request.data.get("email", None)
        password = request.data.get("password", None)

        if not email or not password:
            return self._response(
                {"message": "Both email and password are required.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, email=email, password=password)

        if user:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            subscription = Subscription.objects.filter(user=user).order_by('-created_at').first()
            subscription_data = SubscriptionDetailSerializer(subscription).data if subscription else None

            is_trial_valid, subscription_id = self._check_trial_validity(subscription)

            data = {
                "refresh_token": str(refresh),
                "access_token": str(refresh.access_token),
                "email": email,
                "name": user.name,
                "user_id": user.id,
                "image": request.build_absolute_uri(user.image.url) if user.image else None,
                "subscription": subscription_data,
                "isTrialValid": is_trial_valid
            }
            return self._response(
                {"message": "Logged in successfully.", "data": data},
                status.HTTP_200_OK,
            )
        else:
            return self._response(
                {"message": "Invalid Credentials. Try Again.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

    def _check_trial_validity(self, subscription):
        """
        Check if the user's trial is still valid
        """
        is_trial_valid = None
        subscription_id = None
        if subscription:
            subscription_id = subscription.id
            if subscription.subscription == FREE_SUBSCRIPTION:
                if subscription.is_active and subscription.expiry_date >= timezone.now().date():
                    is_trial_valid = True
                else:
                    is_trial_valid = False
        return is_trial_valid, subscription_id

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class UserLogoutViewSet(viewsets.ViewSet):
    """
    Handle user logout
    """
    permission_classes = [IsAuthenticated]

    def logout(self, request):
        """
        Logout user and blacklist refresh token
        """
        refresh_token = request.data.get("refresh_token", None)

        if not refresh_token:
            return self._response(
                {"message": "Refresh token is required.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return self._response(
                {"message": "User logged out successfully.", "data": {}},
                status.HTTP_200_OK,
            )
        except Exception as e:
            return self._response(
                {"message": "Invalid token or token has already been blacklisted.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class PasswordResetView(APIView):
    """
    Handle password reset requests
    """
    def post(self, request):
        """
        Generate and send password reset link
        """
        email = request.data.get('email')

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return self._response(
                {'message': 'User with this email does not exist.', "data": {}},
                status.HTTP_404_NOT_FOUND
            )

        code = self._generate_unique_code()
        user.uid = code
        user.save()

        reset_url = f"https://emdradmin.pythonanywhere.com/mindmend/reset-password/confirm/?uid={code}"
        self._send_password_reset_email(user.email, reset_url)

        return self._response(
            {'message': 'Password reset link has been sent to your email.'},
            status.HTTP_200_OK
        )

    def _generate_unique_code(self):
        """
        Generate a unique code for password reset
        """
        while True:
            code = random.randint(RANDOM_CODE_MIN, RANDOM_CODE_MAX)
            if not CustomUser.objects.filter(uid=code).exists():
                return code

    def _send_password_reset_email(self, email, reset_url):
        """
        Send password reset email
        """
        text_content = f"Please click the following link to reset your password: {reset_url}"
        html_content = f"""
        <html>
            <body>
                <p>This is an important message.</p>
                <p>Please click the following link to reset your password:</p>
                <a href="{reset_url}">{reset_url}</a>
            </body>
        </html>
        """
        msg = EmailMultiAlternatives(
            "Password Reset Link", text_content, settings.EMAIL_HOST_USER, [email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class PasswordResetConfirmView(APIView):
    """
    Handle password reset confirmation
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Confirm and reset password
        """
        uid = request.data.get('UID')
        new_password = request.data.get('new_password')
        email = request.data.get('email')

        if not uid or not new_password or not email:
            return self._response(
                {"message": "UID, new password, and email are required.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return self._response(
                {'message': 'User with this email does not exist.', "data": {}},
                status.HTTP_404_NOT_FOUND
            )

        if str(user.uid) != uid:
            return self._response(
                {"message": "The reset link is invalid or has expired.", "data": {}},
                status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.uid = None
        user.save()

        return self._response(
            {"message": "Password has been reset successfully.", "data": {"email": email, "user_id": user.id}},
            status.HTTP_200_OK
        )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class ContactUsAPIView(APIView):
    """
    Handle contact messages
    """
    def post(self, request, format=None):
        """
        Save contact message
        """
        serializer = ContactMessageSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if Contact.objects.filter(email=email).exists():
                return self._response(
                    {'message': 'Email already exists in database.', "data": {}},
                    status.HTTP_409_CONFLICT
                )

            contact_instance = serializer.save()
            return self._response(
                {'message': 'Message sent successfully.', 'data': {"email": email, "message": serializer.validated_data['message'], "contact_id": contact_instance.id}},
                status.HTTP_201_CREATED
            )

        return self._response(
            {'message': 'Failed to send message.', 'data': serializer.errors},
            status.HTTP_400_BAD_REQUEST
        )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class UserListAPIView(APIView):
    """
    Retrieve a list of users
    """
    def get(self, request, format=None):
        """
        Get all users
        """
        users = CustomUser.objects.all()

        if not users.exists():
            return self._response(
                {"message": "No users in the database.", "data": []},
                status.HTTP_200_OK
            )

        serializer = CustomUserSerializer(users, many=True)
        names = users.values_list('name', flat=True)

        return self._response(
            {"message": "Users retrieved successfully.", "data": serializer.data, "names": list(names)},
            status.HTTP_200_OK
        )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class UserTherapyInfoAPIView(APIView):
    """
    Handle user therapy info
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Create or update user therapy info
        """
        request_data = request.data.copy()
        request_data['user'] = request.user.id

        scores = Scores.objects.filter(user=request.user).first()
        if scores:
            serializer = ScoresSerializer(scores, data=request_data, partial=True)
        else:
            serializer = ScoresSerializer(data=request_data)

        if serializer.is_valid():
            scores = serializer.save(user=request.user)
            if 'selected_emotions' in request_data:
                scores.selected_emotions.set(request_data['selected_emotions'])
            return self._response(
                {"message": "User therapy info created successfully.", "data": serializer.data},
                status.HTTP_201_CREATED
            )
        return self._response(
            {"message": "Failed to create user therapy info.", "data": serializer.errors},
            status.HTTP_400_BAD_REQUEST
        )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class UserScoreRecordsViewSet(viewsets.ViewSet):
    """
    Handle user score records
    """
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        List all score records for the user
        """
        user = request.user
        score_records = ScoreRecord.objects.filter(user=user)

        if not score_records.exists():
            return self._response(
                {"message": "No scores for the user.", "data": []},
                status.HTTP_200_OK
            )

        serializer = ScoreRecordSerializer(score_records, many=True)
        return self._response(
            {"message": "Score records retrieved successfully.", "data": serializer.data},
            status.HTTP_200_OK
        )

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)


class UserProfileUpdateAPIView(APIView):
    """
    Handle user profile updates
    """
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        """
        Update user profile
        """
        user = request.user
        data = request.data.copy()
        logger.debug(f"Request data: {data}")

        if 'name' in data and data['name'] == user.email:
            return self._response({"message": "name cannot be the same as email.", "data": {}}, status.HTTP_400_BAD_REQUEST)

        if 'image' in data:
            image_file, error_response = self._process_image(data['image'])
            if error_response:
                return error_response
            data['image'] = image_file

        serializer = UserProfileUpdateSerializer(user, data=data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return self._response(
                {"message": "Profile updated successfully.", "data": serializer.data},
                status.HTTP_200_OK
            )
        else:
            return self._response(
                {"message": "Failed to update profile.", "data": serializer.errors},
                status.HTTP_400_BAD_REQUEST
            )

    def _process_image(self, image):
        """
        Process and validate image
        """
        try:
            img = Image.open(image)
            logger.debug(f"Image mode: {img.mode}, Image format: {img.format}")

            if img.mode == 'RGBA':
                img = img.convert('RGB')
                logger.debug("Converted image from RGBA to RGB.")

            img = img.resize((200, 200), Image.LANCZOS)
            buffer = BytesIO()
            img_format = img.format if img.format else 'JPEG'
            img.save(buffer, format=img_format)
            return ContentFile(buffer.getvalue(), name=image.name), None
        except UnidentifiedImageError:
            error_message = "Failed to process image: Unidentified image format."
            logger.error(error_message)
            return None, self._response({"message": error_message, "data": {}}, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            error_message = f"Failed to process image: {str(e)}"
            logger.error(error_message)
            return None, self._response({"message": error_message, "data": {}}, status.HTTP_400_BAD_REQUEST)

    def _response(self, message_data, status_code):
        """
        Generate a consistent response format
        """
        return Response(message_data, status=status_code)
