from django.utils import timezone
from rest_framework import serializers

from Account.models import User, GenerateOTP, GenerateOTPEmail,AdminReferral


class UserSerializer(serializers.ModelSerializer):
    @staticmethod
    def get_user_avatar_url(obj):
        try:
            return obj.avatar.url
        except:
            return None

    @staticmethod
    def get_created_at(obj):
        date_time = timezone.localtime(obj.added_on)
        return date_time.strftime("%d %b, %Y %I:%M %p")

    @staticmethod
    def get_rating(obj):
        return round(float(obj.rating), 2)

    created_at = serializers.SerializerMethodField('get_created_at')
    avatar = serializers.SerializerMethodField('get_user_avatar_url')

    class Meta:
        model = User
        fields = ['id',
                  'username',
                  'email',
                  'phone_no',
                  'country_code',
                  'created_at',
                  'avatar', 'is_email_verify', 'is_verify', 'active', 'admin', 'is_staff']


class GenerateOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = GenerateOTP
        fields = ['phone_no', 'country_code']


class GenerateOTPEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = GenerateOTPEmail
        fields = ['email']


class RegisterSerializer(serializers.ModelSerializer):
    
    referral_code = serializers.CharField(max_length=255)
    otp = serializers.IntegerField()
    email_id = serializers.EmailField()
    avatar = serializers.ImageField(allow_null=True, required=False)
    uname = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)
    code = serializers.CharField(max_length=255, allow_null=True, required=False)
    

    class Meta:
        model = User
        fields = ['tags', 'phone_no', 'application_id', 'otp', 'email_id', 'uname', 'password', 'country_code', 'avatar', 'code','referral_code']


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'application_id']


class LoginGoogleSerializer(serializers.ModelSerializer):
    code = serializers.CharField(max_length=255)
    class Meta:
        model = User
        fields = ['code', 'application_id']


class ForgotPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'application_id']


class ForgotPasswordSerializerEmail(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'application_id']


class ForgotPasswordVerifyStep1Serializer(serializers.ModelSerializer):
    otp = serializers.IntegerField()

    class Meta:
        model = User
        fields = ['otp', 'username', 'application_id']


class ForgotPasswordVerifyStep2Serializer(serializers.ModelSerializer):
    otp = serializers.IntegerField()
    new_password = serializers.CharField(max_length=255, allow_null=False, allow_blank=False)

    class Meta:
        model = User
        fields = ['otp', 'username', 'application_id', 'new_password']


class RegisterSerializerSatpuda(serializers.ModelSerializer):
    email_id = serializers.EmailField()
    avatar = serializers.ImageField(allow_null=True, required=False)
    uname = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)
    token_password = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['tags', 'phone_no', 'application_id', 'email_id', 'uname', 'password', 'country_code', 'avatar', 'token_password']


class AdminReferralSerializer(serializers.ModelSerializer):

    @staticmethod
    def get_admin(obj):
        temp = UserSerializer(obj.admin, many=False)
        #temp.is_valid()
        return temp.data

    admin = serializers.SerializerMethodField()
    class Meta:
        model = AdminReferral
        fields = ['id','admin','referral_code','status','created_at']