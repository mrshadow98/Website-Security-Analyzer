import datetime
import uuid

from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from django.db import models
from django.utils.timezone import utc


class UserManager(BaseUserManager):

    def create_user(self, phone_no, password=None, email=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not phone_no:
            raise ValueError('Users must have an phone')

        user = self.model(
            phone_no=phone_no,
            email=email
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_new_user(self, phone_no, password, is_verify, country_code, email,
                        full_name, application_id, tags, avatar):
        """
        Creates and saves a User with the given email and password.
        """
        if not phone_no:
            raise ValueError('Users must have an phone_no')

        user = self.model(
            phone_no=phone_no,
            is_verify=is_verify,
            country_code=country_code,
            email=email,
            username=full_name,
            application_id=application_id,
            tags=tags,
            avatar=avatar,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_staffuser(self, phone_no, password):
        """
        Creates and saves a staff user with the given email and password.
        """
        user = self.create_user(
            phone_no,
            password=password,
        )
        user.is_ = True
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_no, password):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            phone_no=phone_no,
            password=password,
        )

        user.is_staff = True
        user.is_admin = True
        user.save()
        return user


class User(AbstractBaseUser):
    phone_no = models.CharField(
        verbose_name='phone_no',
        max_length=20,
        unique=True,
    )
    username = models.CharField(
        verbose_name='username',
        max_length=100,
    )
    avatar = models.ImageField(
        verbose_name='avatar',
        upload_to='user/avatar/',
        blank=True,
        null=True
    )
    email = models.CharField(
        verbose_name='email',
        max_length=100,
        blank=True,
        null=True
    )
    application_id = models.CharField(
        verbose_name='app_id',
        max_length=100,
        blank=True,
        null=True
    )
    is_verify = models.BooleanField(
        verbose_name='is_verify',
        default=False
    )
    tags = models.CharField(
        verbose_name='tags',
        max_length=500,
        blank=True,
        null=True
    )
    google_account = models.CharField(
        verbose_name='google_account',
        max_length=500,
        blank=True,
        null=True
    )
    country_code = models.CharField(
        max_length=5,
        null=False,
        default='+91'
    )
    added_on = models.DateTimeField(auto_now_add=True, blank=True)
    active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # a admin user; non super-user
    admin = models.BooleanField(default=False)  # a superuser
    firebase_messaging_token = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )
    is_email_verify = models.BooleanField(
        verbose_name='is_email_verify',
        default=True
    )
    USERNAME_FIELD = 'phone_no'
    REQUIRED_FIELDS = []  # Email & Password are required by default.

    objects = UserManager()

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def verify_email(self, is_verify):
        self.is_email_verify = is_verify
        self.save()
        return is_verify

    def __str__(self):
        return str(self.email) + " " + str(self.username)


class GenerateOTP(models.Model):
    otp = models.IntegerField()
    type = models.CharField(max_length=255, default="register")
    phone_no = models.CharField(max_length=13, null=False)
    country_code = models.CharField(max_length=5)
    attempts = models.IntegerField(default=5)
    global_attempts = models.IntegerField(default=9)
    verify_attempts = models.IntegerField(default=5)
    time_generate_otp = models.DateTimeField(auto_now_add=True, blank=True)

    def get_time_diff(self):
        if self.time_generate_otp:
            now = datetime.datetime.now().utcnow().replace(tzinfo=utc)
            time_difference = now - self.time_generate_otp

            return time_difference.total_seconds()

    def __str__(self):
        return str(self.phone_no)


class ForgotPasswordUser(models.Model):
    application_id = models.CharField(verbose_name='app_id', max_length=100, )
    phone_no_or_email = models.CharField(verbose_name='phone_no_or_email', max_length=100, null=True)
    time_generate_otp = models.DateTimeField(auto_now_add=True)

    def get_time_diff(self):
        if self.time_generate_otp:
            now = datetime.datetime.utcnow().replace(tzinfo=utc)
            time_difference = now - self.time_generate_otp

            return time_difference.total_seconds()

    def __str__(self):
        return "{}".format(self.phone_no)


class BlockedPhoneNumber(models.Model):
    phone_no_or_email = models.CharField(max_length=100, null=True)
    reason = models.CharField(max_length=1000, blank=False)

    def __str__(self):
        return str(self.phone_no)


class DeviceProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    application_id = models.CharField(
        verbose_name='app_id',
        max_length=100,
    )
    device_info = models.TextField(
        verbose_name='device_info'
    )
    harmfullApps = models.TextField(
        verbose_name='harmfull_apps',
        null=True
    )
    is_rooted = models.BooleanField(
        default=True
    )
    is_emulator = models.BooleanField(
        default=True
    )
    basic_integrity = models.BooleanField(
        default=True
    )
    ctc_match = models.BooleanField(
        default=True
    )
    version = models.IntegerField(default=0)
    added_on = models.DateTimeField(auto_now_add=True, blank=True)

    def __str__(self):
        return str(self.user.phone_no)


class GenerateOTPEmail(models.Model):
    otp = models.IntegerField()
    type = models.CharField(max_length=255, default="register")
    email = models.CharField(max_length=100, null=False)
    attempts = models.IntegerField(default=5)
    global_attempts = models.IntegerField(default=9)
    verify_attempts = models.IntegerField(default=5)
    time_generate_otp = models.DateTimeField(auto_now_add=True, blank=True)

    def get_time_diff(self):
        if self.time_generate_otp:
            now = datetime.datetime.utcnow().replace(tzinfo=utc)
            time_difference = now - self.time_generate_otp

            return time_difference.total_seconds()

    def __str__(self):
        return str(self.email)


class AdminReferral(models.Model):
    admin = models.ForeignKey(User, on_delete=models.CASCADE)
    referral_code = models.CharField(max_length=255)
    status = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "Admin: "+str(self.admin.username) + "| Token: " + str(self.referral_code)
