from django.utils import timezone
from rest_framework import serializers
from rest_framework.fields import IntegerField, DateTimeField

from Account.models import User, GenerateOTP, GenerateOTPEmail,AdminReferral
from Account.serializers import UserSerializer
from Analyser.models import RequestData, Result


class ResultSerializer(serializers.ModelSerializer):
    created_at = DateTimeField(required=False, allow_null=True, format='%Y-%m-%dT%H:%M:%S')

    class Meta:
        model = Result
        depth = 2
        fields = '__all__'


class RequestDataSerializer(serializers.ModelSerializer):
    user = UserSerializer(many=False, required=False, allow_null=True)
    result = ResultSerializer(required=False, allow_null=True)
    created_at = DateTimeField(required=False, allow_null=True, format='%Y-%m-%dT%H:%M:%S')

    class Meta:
        model = RequestData
        depth = 2
        fields = '__all__'