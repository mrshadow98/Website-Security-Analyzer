from django.conf.urls import url
from django.urls import path, re_path
from . import views

VERSION = ""

urlpatterns = [
    path("update_token/", views.update_token, name=VERSION + "update_token"),
    # path("verify_email/", views.verify_email, name=VERSION + "verify_email"),
    # path("send_verification_email/", views.send_verification_email, name=VERSION + "send_verification_email"),
    path("register/", views.register, name=VERSION + "register"),
    path("generate_otp/", views.generate_otp, name=VERSION + "generate_otp_email"),
    path("login/", views.login_user, name=VERSION + "login_user"),
    path("forgot_password/", views.forgot_password, name=VERSION + "forgot_password"),
    path("forgot_password_verify_otp/", views.forgot_password_verify_otp,
         name=VERSION+"forgot_password_verify"),
    path("forgot_password_reset_password/", views.forgot_password_reset_password,
         name=VERSION+"forgot_password_reset_password"),
    path("logout/", views.logout_user, name=VERSION + 'logout_user'),
    path("update_profile/", views.update_device_profile, name=VERSION + "update_device_profile"),
    url(r'^user_list/$', views.user_list, name='user_list'),  # create
    url(r'^user_detail/(?P<pk>[0-9]+)/$', views.user_detail, name='user_detail'),  # update, delete
    path('login_user_google/', views.login_user_google),
    url(r'^refferal_code/$', views.refferal_code_list,name='refferal_code_list'),
    url(r'^refferal_code/(?P<pk>[0-9]+)/$', views.referal_code_detail, name='refferal_code_detail'),
]
