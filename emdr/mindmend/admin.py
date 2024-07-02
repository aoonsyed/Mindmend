from django.contrib import admin
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from django.apps import AppConfig
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group, Permission
from .models import CustomUser, Contact, Scores, Subscription, Emotion


class SubscriptionInline(admin.TabularInline):
    model = Subscription
    extra = 0
    readonly_fields = ('amount',)

    def has_add_permission(self, request, obj):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ScoresInline(admin.TabularInline):
    model = Scores
    extra = 0

    def get_selected_emotions(self, obj):
        return ", ".join([e.name for e in obj.selected_emotions.all()])

    get_selected_emotions.short_description = 'Selected Emotions'
    readonly_fields = ('get_selected_emotions',)


class CustomUserAdmin(BaseUserAdmin):
    model = CustomUser

    list_display = (
        'thumbnail', 'username', 'email', 'is_staff',
        'get_subscriptions', 'get_scores'
    )
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'email')

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('email', 'image')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'password', 'email', 'image',
                'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
    )

    ordering = ('username',)
    inlines = [SubscriptionInline, ScoresInline]

    def thumbnail(self, obj):
        if obj.image:
            return mark_safe('<img src="{}" width="30" height="30" style="border-radius:50%;" />'.format(obj.image.url))
        return "-"

    thumbnail.short_description = 'Profile Image'

    def get_subscriptions(self, obj):
        subscriptions = Subscription.objects.filter(user=obj)
        return ", ".join([f"{sub.subscription}: {sub.amount}" for sub in subscriptions])

    get_subscriptions.short_description = 'Subscriptions'

    def get_scores(self, obj):
        scores = Scores.objects.filter(user=obj)
        if scores.exists():
            score = scores.first()
            return f"Before: {score.before_therapy}, " \
                   f"After: {score.after_therapy}, " \
                   f"General Emotion: {score.general_emotion}"
        return "No Scores"

    get_scores.short_description = 'Scores'


class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'created_at')
    search_fields = ('name', 'email')
    list_filter = ('created_at',)


class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'subscription', 'amount', 'expiry_date', 'is_active', 'payment_date')
    list_filter = ('subscription', 'is_active', 'payment_date', 'expiry_date')
    search_fields = ('user__username', 'user__email')

    def save_model(self, request, obj, form, change):
        if obj.subscription == 'monthly':
            obj.amount = 4.00
        elif obj.subscription == 'yearly':
            obj.amount = 29.99
        super().save_model(request, obj, form, change)


class EmotionAdmin(admin.ModelAdmin):
    list_display = ('name',)


class ScoresAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'before_therapy',
        'after_therapy',
        'general_emotion',
        'get_selected_emotions'
    )
    search_fields = ('user__username', 'user__email')
    list_filter = ('before_therapy', 'after_therapy', 'general_emotion')

    def get_selected_emotions(self, obj):
        return ", ".join([e.name for e in obj.selected_emotions.all()])

    get_selected_emotions.short_description = 'Selected Emotions'


admin.site.unregister(Group)  # Unregister the original Group model
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Contact, ContactAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(Emotion, EmotionAdmin)
admin.site.register(Scores, ScoresAdmin)


# Ensure this code runs only after Django is fully initialized
def setup_admin_titles():
    admin.site.site_header = _("MindMend Administration")
    admin.site.site_title = _("MindMend Admin Portal")
    admin.site.index_title = _("Welcome to MindMend Admin Portal")


# Use the ready() method of an AppConfig to defer execution
class AdminConfig(AppConfig):
    name = 'admin'
    verbose_name = "Administration"

    def ready(self):
        setup_admin_titles()


# Make sure to import and use this AppConfig in your installed apps
default_app_config = 'admin.AdminConfig'
