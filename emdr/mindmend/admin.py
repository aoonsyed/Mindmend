from .models import CustomUser, Contact
from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.apps import AppConfig


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

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Contact)
