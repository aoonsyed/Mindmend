from rest_framework import serializers
from .models import CustomUser, Contact, Scores, Emotion, ScoreRecord


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["email", "password"]


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "password"]

    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
        )
        return user


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'message']


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'image']

    def validate_username(self, value):
        user = self.context['request'].user
        if CustomUser.objects.filter(username=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("Username already exists.")
        return value


class ScoresSerializer(serializers.ModelSerializer):
    selected_emotions = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Emotion.objects.all()
    )

    class Meta:
        model = Scores
        fields = ['user', 'before_therapy', 'after_therapy', 'general_emotion', 'selected_emotions']
        extra_kwargs = {
            'user': {'required': False}  # Ensure user is not required during validation
        }

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = instance.user.username  # Assuming you want to show the username instead of the user ID
        representation['selected_emotions'] = [emotion.name for emotion in instance.selected_emotions.all()]
        return representation


class ScoreRecordSerializer(serializers.ModelSerializer):
    selected_emotions = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Emotion.objects.all()
    )

    class Meta:
        model = ScoreRecord
        fields = ['before_therapy', 'after_therapy', 'general_emotion', 'selected_emotions', 'created_at']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['selected_emotions'] = [emotion.name for emotion in instance.selected_emotions.all()]
        return representation