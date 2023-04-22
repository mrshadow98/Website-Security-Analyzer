from django.contrib import admin
from .models import GenerateOTP, DeviceProfile, GenerateOTPEmail

from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .forms import UserAdminCreationForm, UserAdminChangeForm
from .models import User, BlockedPhoneNumber,AdminReferral


# Register your models here.
class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on Account.User.
    list_display = ('phone_no', 'email', 'admin', 'username')
    list_filter = ('admin',)
    fieldsets = (
        (None, {'fields': (
            'phone_no', 'password', 'username', 'email', 'application_id', 'tags', 'country_code',
            'is_verify', 'avatar', 'google_account',
            'is_email_verify', 'firebase_messaging_token', 'is_referral_verify', 'referral_code')}),
        ('Personal info', {'fields': ()}),
        ('Permissions', {'fields': ('admin', 'is_staff', 'active')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'phone_no', 'password1', 'password2', 'username', 'email', 'application_id', 'tags',
                'country_code',
                'is_verify', 'avatar', 'is_email_verify', 'google_account',
                'firebase_messaging_token', 'active')}
         ),
    )
    search_fields = ('phone_no', 'email', 'username', 'id')
    ordering = ('phone_no',)
    filter_horizontal = ()


# Remove Group Model from admin. We're not using it.

class DeviceProfileSearch(admin.ModelAdmin):
    search_fields = ['application_id', 'device_info']


admin.site.unregister(Group)
admin.site.register(User, UserAdmin)
admin.site.register(GenerateOTP)
admin.site.register(DeviceProfile, DeviceProfileSearch)
admin.site.register(GenerateOTPEmail)
admin.site.register(BlockedPhoneNumber)
admin.site.register(AdminReferral)

