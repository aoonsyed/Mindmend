from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import AbstractUser, Group, Permission

class CustomUser(AbstractUser):
    otp_check = models.IntegerField(default=0)
    uid = models.CharField(max_length=500, default="", null=True, blank=True)
    image = models.ImageField(upload_to='profile_images/', blank=True, null=True)

    groups = models.ManyToManyField(
        Group,
        related_name='Customer',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_query_name='user',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions',  # Change this to any unique name
        blank=True,
        help_text='Specific permissions for this user.',
        related_query_name='user',
    )

    def __str__(self):
        return self.username


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.name} - {self.email}'


class Subscription(models.Model):
    SUBSCRIPTION_CHOICES = [
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    subscription = models.CharField(max_length=10, choices=SUBSCRIPTION_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    expiry_date = models.DateField()
    is_active = models.BooleanField(default=True)
    payment_date = models.DateField(auto_now_add=True)
    description = models.TextField(max_length=100)

    def save(self, *args, **kwargs):
        if self.subscription == 'monthly':
            self.amount = 4.00
        elif self.subscription == 'yearly':
            self.amount = 29.99
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.username} - {self.subscription}'


class Emotion(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name


class Scores(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='scores')
    before_therapy = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    after_therapy = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    general_emotion = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    selected_emotions = models.ManyToManyField(Emotion, related_name='current_scores')

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        ScoreRecord.objects.create(
            user=self.user,
            before_therapy=self.before_therapy,
            after_therapy=self.after_therapy,
            general_emotion=self.general_emotion,
        ).selected_emotions.set(self.selected_emotions.all())

    def __str__(self):
        selected_emotions_names = ', '.join([e.name for e in self.selected_emotions.all()])
        return f"{self.user.username} - Before: {self.before_therapy} - After: {self.after_therapy} - General: {self.general_emotion} - Selected: {selected_emotions_names}"


class ScoreRecord(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='score_records')
    before_therapy = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    after_therapy = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    general_emotion = models.IntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    selected_emotions = models.ManyToManyField(Emotion, related_name='score_records')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        selected_emotions_names = ', '.join([e.name for e in self.selected_emotions.all()])
        return f"{self.user.username} - Before: {self.before_therapy} - After: {self.after_therapy} - General: {self.general_emotion} - Selected: {selected_emotions_names} - Created: {self.created_at}"
