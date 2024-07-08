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

@method_decorator(csrf_exempt, name='dispatch')
class UserSignupViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            name = request.data.get('name')
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return Response(
                    {"message": "Both email and password are required.", "data": {}},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if CustomUser.objects.filter(email=email).exists():
                return Response(
                    {"message": "User with this email already exists.", "data": {}},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = CustomUser.objects.create_user(name=name, email=email, password=password)
            user.save()

            return Response(
                {"message": "User created successfully.",
                 "data": {"id": user.id, "name": user.name, "email": user.email}},
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return Response(
                {"message": f"Error: {str(e)}", "data": {}},
                status=status.HTTP_400_BAD_REQUEST
            )

class SubscriptionListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            subscription_plans = [
                {"name": "Free", "description": "Free", "amount": 0,
                 "duration": "14 Days"},
                {"name": "Monthly", "description": "Full Customisation and Tracking.", "amount": 4.00,
                 "duration": "1 month"},
                {"name": "Yearly", "description": "Full Customisation and Tracking.", "amount": 29.99,
                 "duration": "12 months"},
            ]
            return Response(
                {
                    "message": "Subscription plans retrieved successfully.",
                    "data": subscription_plans,
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {
                    "message": f"Error: {str(e)}",
                    "data": {},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SubscriptionCreateView(generics.CreateAPIView):
    serializer_class = SubscriptionCreateSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                {
                    "message": "Subscription created successfully.",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
                headers=headers
            )
        except Exception as e:
            return Response(
                {
                    "message": "Not a valid subscription",
                    "data": serializer.errors if 'serializer' in locals() else {},
                },
                status=status.HTTP_400_BAD_REQUEST
            )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", None)
        password = request.data.get("password", None)

        if not email or not password:
            return Response(
                {"message": "Both email and password are required.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, email=email, password=password)

        if user:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            subscription = Subscription.objects.filter(user=user).order_by('-created_at').first()
            subscription_data = SubscriptionDetailSerializer(subscription).data if subscription else None

            # Check isTrialValid logic
            is_trial_valid = None
            subscription_id = None
            if subscription:
                subscription_id = subscription.id
                if subscription.subscription == "free":
                    if subscription.is_active and subscription.expiry_date >= timezone.now().date():
                        is_trial_valid = True
                    else:
                        is_trial_valid = False

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
            return Response(
                {"message": "Logged in successfully.", "data": data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": "Invalid Credentials. Try Again.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

class UserLogoutViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def logout(self, request):
        refresh_token = request.data.get("refresh_token", None)

        if not refresh_token:
            return Response(
                {"message": "Refresh token is required.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return Response(
                {"message": "User logged out successfully.", "data": {}},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"message": "Invalid token or token has already been blacklisted.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response(
                {'message': 'User with this email does not exist.', "data": {}},
                status=status.HTTP_404_NOT_FOUND
            )

        while True:
            code = random.randint(1000000, 9999999)
            if not CustomUser.objects.filter(uid=code).exists():
                break
        user.uid = code
        user.save()
        reset_url = f" https://emdradmin.pythonanywhere.com/mindmend/reset-password/confirm/?uid={code}"

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
            "Password Reset Link", text_content, settings.EMAIL_HOST_USER, [user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        return Response(
            {'message': 'Password reset link has been sent to your email.'},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        uid = request.data.get('UID')
        new_password = request.data.get('new_password')
        email = request.data.get('email')

        if not uid or not new_password or not email:
            return Response(
                {"message": "UID, new password, and email are required.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response(
                {'message': 'User with this email does not exist.', "data": {}},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            if str(user.uid) != uid:
                raise ValueError("UID does not match")
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist) as e:
            return Response(
                {"message": "The reset link is invalid or has expired.", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.uid = None
        user.save()
        data = {
            "email": email,
            "user_id": user.id,
        }
        return Response(
            {"message": "Password has been reset successfully.", "data": data},
            status=status.HTTP_200_OK
        )

class ContactUsAPIView(APIView):
    def post(self, request, format=None):
        serializer = ContactMessageSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if Contact.objects.filter(email=email).exists():
                return Response(
                    {'message': 'Email already exists in database.', "data": {}},
                    status=status.HTTP_409_CONFLICT
                )

            contact_instance = serializer.save()
            data = {
                'email': email,
                'message': serializer.validated_data['message'],
                'contact_id': contact_instance.id,
            }

            return Response(
                {'message': 'Message sent successfully.', 'data': data},
                status=status.HTTP_201_CREATED
            )

        return Response(
            {'message': 'Failed to send message.', 'data': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

class UserListAPIView(APIView):
    def get(self, request, format=None):
        users = CustomUser.objects.all()

        if not users.exists():
            return Response(
                {"message": "No users in the database."},
                status=status.HTTP_200_OK
            )

        serializer = CustomUserSerializer(users, many=True)
        names = users.values_list('name', flat=True)

        return Response(
            {
                "message": "Users retrieved successfully.",
                "data": serializer.data,
                "names": list(names)
            },
            status=status.HTTP_200_OK
        )

class UserTherapyInfoAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
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
            return Response(
                {"message": "User therapy info created successfully.", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(
            {"message": "Failed to create user therapy info.", "data": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

class UserScoreRecordsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        user = request.user
        score_records = ScoreRecord.objects.filter(user=user)

        if not score_records.exists():
            return Response(
                {"message": "No scores for the user.", "data": []},
                status=status.HTTP_200_OK
            )

        serializer = ScoreRecordSerializer(score_records, many=True)
        return Response(
            {"message": "Score records retrieved successfully.", "data": serializer.data},
            status=status.HTTP_200_OK
        )


import logging
logger = logging.getLogger(__name__)

class UserProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = request.user
        data = request.data.copy()

        # Log the incoming request data
        logger.debug(f"Request data: {data}")

        # Ensure that name and email are not mixed up
        if 'name' in data and data['name'] == user.email:
            response = {"message": "name cannot be the same as email.", "data": {}}
            logger.debug(f"Response: {response}")
            return Response(
                response,
                status=status.HTTP_400_BAD_REQUEST
            )

        if 'image' in data and data['image'] is not None:
            try:
                image = data['image']
                img = Image.open(image)

                # Log the image mode and format
                logger.debug(f"Image mode: {img.mode}, Image format: {img.format}")

                # Convert RGBA to RGB if necessary
                if img.mode == 'RGBA':
                    img = img.convert('RGB')
                    logger.debug("Converted image from RGBA to RGB.")

                # Resize the image while maintaining its format
                img = img.resize((200, 200), Image.LANCZOS)
                buffer = BytesIO()
                img_format = img.format if img.format else 'JPEG'  # Use original format or default to JPEG
                img.save(buffer, format=img_format)
                image_file = ContentFile(buffer.getvalue(), name=image.name)
                data['image'] = image_file
            except UnidentifiedImageError:
                error_message = "Failed to process image: Unidentified image format."
                logger.error(error_message)
                return Response(
                    {"message": error_message, "data": {}},
                    status=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                error_message = f"Failed to process image: {str(e)}"
                logger.error(error_message)
                return Response(
                    {"message": error_message, "data": {}},
                    status=status.HTTP_400_BAD_REQUEST
                )

        serializer = UserProfileUpdateSerializer(user, data=data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            response_data = {
                "message": "Profile updated successfully.",
                "data": serializer.data,
            }
            logger.debug(f"Response: {response_data}")
            return Response(
                response_data,
                status=status.HTTP_200_OK
            )
        else:
            error_message = {"message": "Failed to update profile.", "data": serializer.errors}
            logger.debug(f"Response: {error_message}")
            return Response(
                error_message,
                status=status.HTTP_400_BAD_REQUEST
            )