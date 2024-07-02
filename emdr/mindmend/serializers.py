from rest_framework import serializers
from .models import CustomUser, Contact, Scores


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
    class Meta:
        model = Scores
        fields = ['user', 'before_therapy', 'after_therapy', 'general_emotion', 'selected_emotions']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = instance.user.username  # Assuming you want to show the username instead of the user ID
        representation['selected_emotions'] = [emotion.name for emotion in instance.selected_emotions.all()]
        return representation


