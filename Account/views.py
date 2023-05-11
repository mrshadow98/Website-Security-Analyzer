import random
import datetime
import hashlib
import urllib
import uuid
import boto3
import random
import requests
from django.core.exceptions import ValidationError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template import loader
from django.contrib.auth import authenticate, login, logout
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from social_django.utils import psa
from Account.models import User, GenerateOTP, ForgotPasswordUser, DeviceProfile, GenerateOTPEmail,AdminReferral
from WebsiteSecurityAnalyser import settings
from .serializers import RegisterSerializer, GenerateOTPSerializer, LoginSerializer, \
    ForgotPasswordSerializer, ForgotPasswordVerifyStep1Serializer, ForgotPasswordVerifyStep2Serializer, \
    GenerateOTPEmailSerializer, ForgotPasswordSerializerEmail, UserSerializer, RegisterSerializerSatpuda, \
    LoginGoogleSerializer,AdminReferralSerializer
from .tasks import SendEmailTask, send_mass_html_mail

RATE_LIMITING_WAIT_TIME = 60 * 30


@api_view(['POST'])
@permission_classes([AllowAny])
def generate_otp(request):
    serializer = GenerateOTPSerializer(data=request.data)
    if serializer.is_valid():
        phone_no = serializer.validated_data['phone_no']
        country_code = serializer.validated_data['country_code']

        if len(str(phone_no)) + len(str(country_code)) > 13:
            return Response({'error': True, 'message': 'Mobile number is not valid!', 'token': None})

        if User.objects.filter(phone_no=serializer.validated_data['phone_no']).exists():
            return Response({'error': True, 'message': 'Phone number already exist with another user',
                             'token': None})

        random_number_list = [random.randint(0, 9) for p in range(0, 6)]
        otp = ''.join(str(letter) for letter in random_number_list)

        otp_data = {'country_code': str(country_code), 'phone_no': str(phone_no), 'otp': otp}

        if not GenerateOTP.objects.filter(phone_no=phone_no):
            obj = GenerateOTP(phone_no=phone_no, country_code=country_code, attempts=5, otp=otp)
            obj.save()

        obj = GenerateOTP.objects.get(phone_no=phone_no)
        obj.attempts = obj.attempts - 1
        obj.save()

        if obj.attempts <= 0:
            if obj.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                return Response({'error': True,
                                 'message': 'Too many tries, please wait {0} seconds'
                                .format(RATE_LIMITING_WAIT_TIME - int(obj.get_time_diff())),
                                 'token': None})
            obj.time_generate_otp = datetime.datetime.now()
            obj.attempts = 5
            obj.save()
            print('attempts set to 5 -> ', obj.attempts)
        obj.otp = otp
        obj.save()
        res = send_otp(otp_data)
        return JsonResponse({'error': False, 'message': res})
    else:
        return JsonResponse({'error': True, 'message': serializer.errors}, status=400)


def send_otp_email(data):
    app_name: str = str(settings.APP_NAME)
    message = data['otp'] + " is your verification code for " + app_name + "." + "\nGENIOBITS PVT LTD"
    html_message = get_html_email("Hello User" + ", " + message, "Verification Code: " + data['otp'],
                                  "", "Open App", None)
    email_tuple_list = [("Email Verification Code for your " + app_name + " account!",
                         "", html_message, app_name + "<" + settings.DEFAULT_FROM_EMAIL + ">",
                         [data['email']])]
    emails_tuple = tuple(email_tuple_list)
    mail_res = send_mass_html_mail(emails_tuple)
    # # print response if you want
    response = {'error': False, 'message': 'Sms sent! ' + str(mail_res), 'token': None}
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def generate_otp_email(request):
    if request.method == "POST":
        serializer = GenerateOTPEmailSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            if User.objects.filter(email=email).exists():
                return Response({'error': True, 'message': 'Email already exist with another user',
                                 'token': None})

            random_number_list = [random.randint(0, 9) for p in range(0, 6)]
            otp = ''.join(str(letter) for letter in random_number_list)

            otp_data = {'email': str(email), 'otp': otp}

            if not GenerateOTPEmail.objects.filter(email=email):
                obj = GenerateOTPEmail(email=email, attempts=5, otp=otp)
                obj.save()

            obj = GenerateOTPEmail.objects.get(email=email)
            obj.attempts = obj.attempts - 1
            obj.save()

            if obj.attempts <= 0:
                if obj.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                    return Response({'error': True,
                                     'message': 'Too many tries, please wait {0} seconds'
                                    .format(RATE_LIMITING_WAIT_TIME - int(obj.get_time_diff())),
                                     'token': None})
                obj.time_generate_otp = datetime.datetime.now()
                obj.attempts = 5
                obj.save()
                print('attempts set to 5 -> ', obj.attempts)

            obj.otp = otp
            obj.save()
            res = send_otp_email(otp_data)
            return Response(res)

        return Response({'error': True, 'message': 'Data is not valid!', 'token': None})


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = User.objects.get(phone_no=serializer.validated_data['username'])
        phone_no = user.phone_no
        country_code = user.country_code

        # create record in forgot password table
        random_number_list = [random.randint(0, 9) for p in range(0, 6)]
        otp = ''.join(str(letter) for letter in random_number_list)

        otp_data = {'country_code': str(country_code), 'phone_no': str(phone_no), 'otp': otp}

        if not GenerateOTP.objects.filter(phone_no=phone_no, type="forget"):
            obj = GenerateOTP(phone_no=phone_no, type="forget", country_code=country_code, attempts=5, otp=otp)
            obj.save()

        obj = GenerateOTP.objects.get(phone_no=phone_no, type="forget")
        obj.attempts = obj.attempts - 1
        obj.save()

        # send otp to mobile number -> check rate limiting
        if obj.attempts <= 0:
            if obj.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                return Response({'error': True,
                                 'message': 'Too many tries, please wait {0} seconds'
                                .format(RATE_LIMITING_WAIT_TIME - int(obj.get_time_diff())),
                                 'token': None})

            obj.time_generate_otp = datetime.datetime.now()
            obj.attempts = 5
            obj.save()
            print('attempts set to 5 -> ', obj.attempts)

        obj.otp = otp
        obj.save()

        return Response(send_otp(otp_data))
    return HttpResponse(serializer.errors)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_email(request):
    serializer = ForgotPasswordSerializerEmail(data=request.data)
    if serializer.is_valid():
        user = User.objects.get(email=serializer.validated_data['username'])
        email = user.email

        # create record in forgot password table
        random_number_list = [random.randint(0, 9) for p in range(0, 6)]
        otp = ''.join(str(letter) for letter in random_number_list)

        otp_data = {'email': str(email), 'otp': otp}

        if not GenerateOTPEmail.objects.filter(email=email, type="forget"):
            obj = GenerateOTPEmail(email=email, type="forget", attempts=5, otp=otp)
            obj.save()

        obj = GenerateOTPEmail.objects.get(email=email, type="forget")
        obj.attempts = obj.attempts - 1
        obj.save()

        # send otp to mobile number -> check rate limiting
        if obj.attempts <= 0:
            if obj.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                return Response({'error': True,
                                 'message': 'Too many tries, please wait {0} seconds'
                                .format(RATE_LIMITING_WAIT_TIME - int(obj.get_time_diff())),
                                 'token': None})

            obj.time_generate_otp = datetime.datetime.now()
            obj.attempts = 5
            obj.save()
            print('attempts set to 5 -> ', obj.attempts)

        obj.otp = otp
        obj.save()

        return Response(send_otp_email(otp_data))
    return HttpResponse(serializer.errors)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_verify_otp(request):
    serializer = ForgotPasswordVerifyStep1Serializer(data=request.data)
    if serializer.is_valid():
        user_otp = serializer.validated_data['otp']
        user_username = serializer.validated_data['username']
        # user_password = serializer.validated_data['new_password']
        user_application_id = serializer.validated_data['application_id']

        # if len(user_password) < 6:
        #     return Response({'error': True,
        #                      'message': 'Password too short!!! Try password with more than 5 characters'})

        server_otps = GenerateOTP.objects.filter(phone_no=user_username, type="forget").order_by('-id')
        if server_otps.count() == 0:
            return Response({'error': True, 'message': 'No record found!'})

        # verify otp api view
        server_otp = server_otps[0]
        if server_otp.otp != user_otp:
            return Response({'error': True, 'message': 'OTP is not valid!'})

        forgot_password_object = ForgotPasswordUser(application_id=user_application_id, phone_no_or_email=user_username)
        forgot_password_object.save()

        server_otps.delete()

        return Response({'error': False, 'message': 'OTP is valid, send new password!'})
    else:
        return Response({'error': True, 'message': '{}'.format(serializer.errors)})


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_verify_otp_email(request):
    serializer = ForgotPasswordVerifyStep1Serializer(data=request.data)

    if serializer.is_valid():
        user_otp = serializer.validated_data['otp']
        user_username = serializer.validated_data['username']
        # user_password = serializer.validated_data['new_password']
        user_application_id = serializer.validated_data['application_id']

        # if len(user_password) < 6:
        #     return Response({'error': True,
        #                      'message': 'Password too short!!! Try password with more than 5 characters'})

        server_otps = GenerateOTPEmail.objects.filter(email=user_username, type="forget").order_by('-id')
        if server_otps.count() == 0:
            return Response({'error': True, 'message': 'No record found!'})

        # verify otp api view
        server_otp = server_otps[0]
        if server_otp.otp != user_otp:
            return Response({'error': True, 'message': 'OTP is not valid!'})

        forgot_password_object = ForgotPasswordUser(application_id=user_application_id, phone_no_or_email=user_username)
        forgot_password_object.save()

        server_otps.delete()

        return Response({'error': False, 'message': 'OTP is valid, send new password!'})
    else:
        return Response({'error': True, 'message': '{}'.format(serializer.errors)})


# delete record and reset password given by user
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_reset_password(request):
    serializer = ForgotPasswordVerifyStep2Serializer(data=request.data)

    if serializer.is_valid():
        ForgetPassObjs = ForgotPasswordUser.objects.filter(application_id=serializer.validated_data['application_id'],
                                                           phone_no_or_email=serializer.validated_data[
                                                               'username']).order_by(
            '-id')
        if ForgetPassObjs.count() == 0:
            return Response({'error': True, 'message': 'No record found!'})

        object_forgot_password_user = ForgetPassObjs[0]

        if object_forgot_password_user.get_time_diff() > 600:
            object_forgot_password_user.delete()
            return Response({'error': True, 'message': 'New password submitted late! Try Again'})

        user_main = User.objects.get(phone_no=serializer.validated_data['username'])
        user_main.set_password(serializer.validated_data['new_password'])
        user_main.save()

        ForgetPassObjs.delete()

        return Response({'error': False, 'message': 'New Password set successfully!!!'})
    else:
        return Response({'error': True, 'message': '{}'.format(serializer.errors)})


# delete record and reset password given by user
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_reset_password_email(request):
    serializer = ForgotPasswordVerifyStep2Serializer(data=request.data)

    if serializer.is_valid():
        ForgetPassObjs = ForgotPasswordUser.objects.filter(application_id=serializer.validated_data['application_id'],
                                                           phone_no_or_email=serializer.validated_data[
                                                               'username']).order_by(
            '-id')
        if ForgetPassObjs.count() == 0:
            return Response({'error': True, 'message': 'No record found!'})

        object_forgot_password_user = ForgetPassObjs[0]

        if object_forgot_password_user.get_time_diff() > 600:
            object_forgot_password_user.delete()
            return Response({'error': True, 'message': 'New password submitted late! Try Again'})

        user_main = User.objects.get(email=serializer.validated_data['username'])
        user_main.set_password(serializer.validated_data['new_password'])
        user_main.save()

        ForgetPassObjs.delete()

        return Response({'error': False, 'message': 'New Password set successfully!!!'})
    else:
        return Response({'error': True, 'message': '{}'.format(serializer.errors)})


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    if request.method == "POST":
        serializer = RegisterSerializer(data=request.data)
        access_token = None
        try:
            access_token = serializer.validated_data['code']
        except:
            pass
        if serializer.is_valid():
            if User.objects.filter(email=serializer.validated_data['phone_no']).exists():
                return Response({'error': True, 'message': 'email id already exist', 'token': None})

            if not GenerateOTP.objects.filter(phone_no=serializer.validated_data['phone_no']).exists():
                return Response({'error': True,
                                 'message': 'We don\'t have any record with the number',
                                 'token': None})

            otp_object = GenerateOTP.objects.get(phone_no=serializer.validated_data['phone_no'])
            otp_object.verify_attempts = otp_object.verify_attempts - 1
            print('verify_attempt', otp_object.verify_attempts, otp_object.phone_no)
            otp_object.save()

            if otp_object.verify_attempts <= 0:
                if otp_object.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                    return Response({'error': True,
                                     'message': 'Too many tries!!!, please wait {0} seconds'
                                    .format(RATE_LIMITING_WAIT_TIME - int(otp_object.get_time_diff())),
                                     'token': None})
                otp_object.delete()
                return Response({'error': True,
                                 'message': 'Too many attempts!!!, Please try with new otp',
                                 'token': None})
            stored_otp = otp_object.otp

            if stored_otp != serializer.validated_data['otp']:
                return Response({'error': True, 'message': 'OTP does not matched',
                                 'token': None})
            avatar = request.FILES.get("avatar")
            user_account = User.objects.create_new_user(is_verify=True,
                                                        is_referral_verify=True,
                                                        phone_no=serializer.validated_data['phone_no'],
                                                        avatar=avatar,
                                                        country_code=serializer.validated_data['country_code'],
                                                        email=serializer.validated_data['email_id'],
                                                        full_name=serializer.validated_data['uname'],
                                                        password=serializer.validated_data['password'],
                                                        application_id=serializer.validated_data['application_id'],
                                                        tags=serializer.validated_data['tags']
                                                        )

            if access_token:
                try:
                    data = google_get_user_info(access_token)
                    if data['sub']:
                        if User.objects.filter(google_account=data['sub']).exists():
                            return JsonResponse({'error': True, 'message': 'Account already exists', 'token': None},
                                                status=400)
                        print(data)
                        user_account.google_account = data['sub']
                        user_account.save()
                    else:
                        return JsonResponse({'error': True, 'message': 'Invalid Token', 'token': None}, status=400)
                except:
                    return JsonResponse({'error': True, 'message': 'Invalid Token', 'token': None}, status=400)
            else:
                user_account.save()
            # update1
            token = Token.objects.create(user=user_account)
            # deleting the record from generate otp
            otp_object.delete()
            try:
                send_verification_email_reg(user_account.email)
            except Exception as e:
                print(str(e))
            user_data = UserSerializer(user_account, many=False).data
            data = {'error': False,
                    'message': 'user registration successful',
                    'token': token.key,
                    'user': user_data,
                    }
            try:
                user_data["token"] = token.key
            except Exception as e:
                print('login:' + str(e))
            print(data)
            return Response(data)
        else:
            print(serializer.errors)
            return Response({'error': True, 'message': serializer.errors, 'token': None})
    return Response({'error': True, 'message': 'request type was invalid!!!'})


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    if request.method == 'POST':
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user_account = authenticate(request, phone_no=username, password=password)

            # Wrong credentials condition
            if not user_account:
                return Response({'error': True,
                                 'message': 'Please check your credentials!',
                                 'token': None})

            login(request, user_account)

            # Creating new authentication token process
            if Token.objects.filter(user=user_account).exists():
                token = Token.objects.get(user=user_account)
                token.delete()
            token = Token.objects.create(user=user_account)
            if request.is_ajax():
                request.session['token'] = token

            user_account.token = token.key
            user_account.application_id = serializer.validated_data['application_id']
            user_account.save()

            if not user_account.is_verify:
                return Response({'error': True, 'message': 'Account not verified!', 'token': None})

            user_data = UserSerializer(user_account, many=False).data
            data = {'error': False,
                    'message': 'user login successful',
                    'token': token.key,
                    'user': user_data
                    }
            try:
                user_data["token"] = token.key
            except Exception as e:
                print('login:' + str(e))

            return Response(data)
        else:
            return Response({'error': True, 'message': 'Please provide valid data ! {}'.format(serializer.errors),
                             'token': None})
    else:
        return Response({'error': True, 'message': 'Please provide valid data!', 'token': None})


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user_google(request):
    if request.method == 'POST':
        serializer = LoginGoogleSerializer(data=request.data)
        if serializer.is_valid():
            access_token = serializer.validated_data['code']
            data = None
            try:
                data = google_get_user_info(access_token)
                uid = data['sub']
            except:
                return JsonResponse({'error': True,
                                     'message': 'Please check your credentials!',
                                     'token': None}, status=403)
            if not User.objects.filter(google_account=data['sub']).exists():
                return JsonResponse({'error': True,
                                     'message': 'Please register before login using this account!',
                                     'token': None}, status=400)
            user_account = User.objects.get(google_account=data['sub'])
            # Creating new authentication token process
            if Token.objects.filter(user=user_account).exists():
                token = Token.objects.get(user=user_account)
                token.delete()
            token = Token.objects.create(user=user_account)

            user_account.application_id = serializer.validated_data['application_id']
            user_account.save()

            if not user_account.is_verify:
                return Response({'error': True, 'message': 'Account not verified!', 'token': None})

            user_data = UserSerializer(user_account, many=False).data
            data = {'error': False,
                    'message': 'user login successful',
                    'token': token.key,
                    'user': user_data
                    }
            try:
                user_data["token"] = token.key
            except Exception as e:
                print('login:' + str(e))

            return Response(data)
        else:
            return Response({'error': True, 'message': 'Please provide valid data ! {}'.format(serializer.errors),
                             'token': None})
    else:
        return Response({'error': True, 'message': 'Please provide valid data!', 'token': None})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    if request.method == 'POST':
        token = request.user.auth_token
        if Token.objects.filter(key=token).exists():
            token = Token.objects.get(key=token)
            token.delete()
            logout(request)
            return Response({'error': False, 'message': 'You\'re successfully logged out!', 'token': None})
        else:
            return Response({'error': True, 'message': 'You are already logged out!', 'token': None})

    return Response({'error': True, 'message': 'Post method required!', 'token': None})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_device_profile(request):
    if request.method == 'POST':
        token = request.user.auth_token
        deviceInfo = request.POST.get("deviceInfo")
        isEmulator = request.POST.get("isEmulator")
        isRooted = request.POST.get("isRooted")
        basicIntegrity = request.POST.get("basicIntegrity")
        ctcMatch = request.POST.get("ctcMatch")
        hash_device = request.POST.get("hash")
        application_id = request.POST.get("application_id")
        harmfullApps = request.POST.get("harmfullApps")
        version = 0
        try:
            version = request.POST.get("version")
        except:
            pass
        if version is None:
            version = 0
        if Token.objects.filter(key=token).exists():
            token = Token.objects.get(key=token)
            user = token.user
            if DeviceProfile.objects.filter(application_id=application_id).exists():
                DeviceProfile.objects.filter(application_id=application_id).update(user=user, device_info=deviceInfo,
                                                                                   is_rooted=isRooted,
                                                                                   is_emulator=isEmulator,
                                                                                   basic_integrity=basicIntegrity,
                                                                                   ctc_match=ctcMatch,
                                                                                   harmfullApps=harmfullApps,
                                                                                   version=version)

            else:
                DeviceProfile(user=user, application_id=application_id, device_info=deviceInfo, is_rooted=isRooted,
                              is_emulator=isEmulator, basic_integrity=basicIntegrity, ctc_match=ctcMatch,
                              harmfullApps=harmfullApps, version=version).save()
            return Response({'error': False, 'message': 'Profile Updated!', 'token': None})
        else:
            return Response({'error': True, 'message': 'You are already logged out!', 'token': None})

    return Response({'error': True, 'message': 'Post method required!', 'token': None})


def send_otp(data):
    app_name = str(settings.APP_NAME)
    if len(str(app_name)) > 29:
        app_name = str(app_name)[0:29]
    message = data['otp'] + " is your verification code for " + app_name + ". #" + settings. \
        APP_SMS_HASH + "\nGENIOBITS PVT LTD"
    send_message(data['country_code'], data['phone_no'], message, "Verification Code")
    # # print response if you want
    response = {'error': False, 'message': 'sms sent!', 'token': None}
    return response


def send_message(country_code, phone_no, message, subject):
    mobile = country_code + phone_no
    # AWS_S3_REGION_NAME = 'ap-south-1'
    # # get response
    # client = boto3.client(
    #     "sns",
    #     aws_access_key_id="TOKEN",
    #     aws_secret_access_key="SECRET",
    #     region_name=AWS_S3_REGION_NAME
    # )
    # # Send your sms message.
    # res = client.publish(
    #     PhoneNumber=mobile,
    #     Message=message,
    #     MessageAttributes={
    #         'AWS.SNS.SMS.SMSType': {
    #             'DataType': 'String',
    #             'StringValue': 'Transactional'
    #         },
    #     }
    # )
    # get response
    return str(message)
    data = urllib.parse.urlencode({'apikey': "hHR/hNwrvTo-vvcRXBKjNsvIabQSIJYI8afM5j8Sie", 'numbers': mobile,
                                   'message': message, 'sender': "GEBITS"})
    data = data.encode('utf-8')
    request = urllib.request.Request("https://api.textlocal.in/send/?")
    f = urllib.request.urlopen(request, data)
    res = f.read()
    return str(res)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_verification_email(request):
    email = request.POST.get("email_id")
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        if not user.is_email_verify:
            random_number_list = [random.randint(0, 9) for p in range(0, 6)]
            otp = ''.join(str(letter) for letter in random_number_list)
            if not GenerateOTPEmail.objects.filter(email=email):
                obj = GenerateOTPEmail(email=email, attempts=5, otp=otp)
                obj.save()

            obj = GenerateOTPEmail.objects.get(email=email)
            obj.attempts = obj.attempts - 1
            obj.save()

            if obj.attempts <= 0:
                if obj.get_time_diff() < RATE_LIMITING_WAIT_TIME:
                    return Response({'error': True,
                                     'message': 'Too many tries, please wait {0} seconds'
                                    .format(RATE_LIMITING_WAIT_TIME - int(obj.get_time_diff())),
                                     'token': None})
                obj.time_generate_otp = datetime.datetime.now()
                obj.attempts = 5
                obj.save()
                print('attempts set to 5 -> ', obj.attempts)

            obj.otp = otp
            obj.save()
            verification_url = settings.BASE_URL + 'account/verify_email/?email=' + email + \
                               '&otp=' + otp + '&hash=' + \
                               hashlib.sha1(str(email + otp + 'lawcsaltemail')
                                            .encode('utf-8')).hexdigest()
            mail_res = send_email(user_object_list=[user, ], subject="Email Verification",
                                  body="Hey " + user.username + ", You are almost ready to enjoy HRMS. Simply "
                                                                "click the below black button to verify email! ",
                                  app_url=verification_url,
                                  course_name="",
                                  button_name="Verify Email", is_verification=True)
            if mail_res != 0:
                return Response({'error': False,
                                 'message': 'Please check your inbox, we have sent you the email',
                                 'number': mail_res})
            else:
                return Response({'error': True,
                                 'message': 'Please try again later, Something went wrong!',
                                 'number': mail_res})
        else:
            return Response({'error': True,
                             'message': 'Your email is already Verified',
                             'number': 0})
    else:
        return Response({'error': True,
                         'message': 'Please try again later, Something went wrong!',
                         'number': 0})


def verify_email(request):
    if request.method == 'GET':
        email = request.GET.get('email')
        otp = request.GET.get('otp')
        hash_request = request.GET.get('hash')
        hash_server = hashlib.sha1(str(email + otp + 'lawcsaltemail').encode('utf-8')).hexdigest()

        if hash_server == hash_request:
            user = User.objects.get(email=email)
            if not GenerateOTPEmail.objects.filter(email=email).exists():
                return Response({'error': True,
                                 'message': 'We don\'t have any record with the number',
                                 'token': None})

            otp_object = GenerateOTPEmail.objects.get(email=email)
            otp_object.verify_attempts = otp_object.verify_attempts - 1
            otp_object.save()
            stored_otp = otp_object.otp
            if stored_otp == int(otp):
                otp_object.delete()
                user.verify_email(is_verify=True)
                return render(request, 'authentication/success_verification.html',
                              {'msg': 'Your email successfully verified. Please login!',
                               'url': settings.BASE_URL + '/'})
            else:
                return render(request, 'authentication/success_verification.html',
                              {'msg': 'Your email not verified, link expired . Please try again!',
                               'url': settings.BASE_URL + '/'})
        else:
            return render(request, 'authentication/success_verification.html',
                          {'msg': 'Your email not verified, link expired . Please try again!',
                           'url': settings.BASE_URL + '/'})


def send_verification_email_reg(email):
    email = email
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        return send_email(user_object_list=[user, ], subject="Thanks for registering",
                          body="Hey " + user.username + ", Thank you for registering with us. You are ready to use "
                                                        "HRMS. If you want to unsubscribe for "
                                                        "email notifications from us. Please contact us at "
                                                        "contact@geniobits.com",
                          app_url=None,
                          course_name="",
                          button_name="Open app", is_verification=True)
    else:
        return Response("We have no such user!")


def get_html_email(body, subject, course_name, button_name, app_url):
    facebook_url = settings.facebook_url
    twitter_url = settings.twitter_url
    instagram_url = settings.instagram_url
    linkdln_url = settings.linkdln_url
    email = settings.email
    address = settings.address
    app_name = settings.APP_NAME
    if app_url is None:
        app_url = settings.app_url
    html_message = loader.render_to_string(
        'authentication/email.html',
        {
            'body': body,
            'facebook_url': facebook_url,
            'twitter_url': twitter_url,
            'instagram_url': instagram_url,
            'linkdln_url': linkdln_url,
            'email': email,
            'address': address,
            'app_url': app_url,
            'course_name': course_name,
            'button_name': button_name,
            'subject': subject,
            'app_name': app_name
        }
    )
    return html_message


def send_email(user_object_list, subject, body, course_name, button_name, app_url,
               is_verification=False):
    app_name = str(settings.APP_NAME)
    user_list = []
    for usr in user_object_list:
        user_list.append(
            {"id": usr.id, "email": usr.email, "firebase_messaging_token": usr.firebase_messaging_token})
    res = SendEmailTask.delay(subject, app_name, user_list, body,
                              course_name, button_name, app_url)
    print(res)
    return "send email thread started"


def send_push_notification(message, title, userlist):
    pass
    # user_list = []
    # for usr in userlist:
    #     user_list.append({"id": usr.id, "email": usr.email, "firebase_messaging_token":usr.firebase_messaging_token})
    # if institute.notifications:
    #     pass
    # SendPushNotificationTask.delay(message, title, userlist, institute.id, institute.FIREBASE_SERVER_KEY)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_token(request):
    token = request.POST.get("token")
    user = request.user
    if user:
        User.objects.filter(firebase_messaging_token=token).update(firebase_messaging_token=None)
        user.firebase_messaging_token = token
        user.save()
    return Response({'error': False, 'message': 'token updated!', 'token': None})


@api_view(['GET'])
@permission_classes([AllowAny])
def user_list(request):
    """
    :param request:
    :return: GET -> Organisation details, POST ->  Create Organisation
    """
    if request.method == "GET":
        items = User.objects.order_by("pk")
        serializer = UserSerializer(items, many=True)
        return Response(serializer.data)


@api_view(['GET', 'PUT'])
@permission_classes([AllowAny])
def user_detail(request, pk):
    """
    :param request:
    :param pk: ID of organisation
    :return: GET -> Organisation data, PUT -> Update Organisation, DELETE -> Deletes organisation
    """
    try:
        item = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = UserSerializer(item, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == "PUT":
        serializer = UserSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def google_get_user_info(code):
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#callinganapi
    access_token = google_get_access_token(code=code)
    response = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        params={'access_token': access_token}
    )

    if not response.ok:
        raise ValidationError('Failed to obtain user info from Google.')
    print(response.json(), 'data')
    return response.json()


def google_get_access_token(*, code: str) -> str:
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens
    data = {
        'code': code,
        'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
        'client_secret': settings.GOOGLE_OAUTH2_CLIENT_SECRET,
        'redirect_uri': settings.REDIRECT_URL,
        'grant_type': 'authorization_code'
    }

    response = requests.post("https://oauth2.googleapis.com/token", data=data)
    print('in it')
    if not response.ok:
        raise ValidationError('Failed to obtain access token from Google.')

    access_token = response.json()['access_token']
    return access_token

# TODO API to manage referel by admin [CURD]


@api_view(['GET','POST'])
@permission_classes([IsAuthenticated])
def refferal_code_list(request):
    if not request.user.admin:
        return JsonResponse({'error': True, 'message': 'Not an admin account'},status=401)

    if request.method == 'GET':

        qst = AdminReferral.objects.all()
        serializer = AdminReferralSerializer(qst,many=True)
        
        return Response({'error': False, 'message': 'All codes','body':serializer.data},status=200)

    if request.method == 'POST':
        
        ref_code = random.randrange(111111, 999999, 6)
        AdminReferral(admin=request.user,referral_code=ref_code,status=False).save()

        return Response({'error': False, 'message': 'Code generated'},status=200)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def referal_code_detail(request,pk):

    if not request.user.admin:
        return JsonResponse({'error': True, 'message': 'Not an admin account'},status=401)
 
    if request.method == 'DELETE':
        try:
            item = AdminReferral.objects.get(pk=pk)
        except AdminReferral.DoesNotExist:
            return Response({'error': True, 'message': 'Code Doesnt exist.'},status=404)

        if item:
            if item.status == True:
                return Response({'error': True, 'message': 'Code Already Used.Cannot Delete!!'},status=400)
            temp_code = item.referral_code
            item.delete()
            return Response({'error': False, 'message': 'Code {} Deleted'.format(temp_code)})
        return Response({'error': True, 'message': 'Code Doesnt exist.'})
    
    
