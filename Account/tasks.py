from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template import loader
from fcm_django.fcm import fcm_send_bulk_message

from WebsiteSecurityAnalyser import settings

logger = get_task_logger(__name__)


@shared_task(name="SendEmailTask")
def SendEmailTask(subject, app_name, user_object_list, body, course_name, button_name, app_url):
    """sends an email when feedback form is filled successfully"""
    print("sending emails")
    try:

        html_message = get_html_email(body, subject, course_name, button_name, app_url)
        email_tuple_list = []
        for user in user_object_list:
            email_tuple_list.append(
                (subject, '', html_message, app_name + "<" + settings.DEFAULT_FROM_EMAIL + ">",
                 [user["email"]]))
            print(user["email"])
        emails_tuple = tuple(email_tuple_list)
        res = send_mass_html_mail(emails_tuple)
        # add_notification_history(user_object_list, subject, body, "res", institute_id,
        #                          history_types.EMAIL)

        if False:
            try:
                registrationIdList = []
                for user in user_object_list:
                    if user["firebase_messaging_token"] != "":
                        registrationIdList.append(user["firebase_messaging_token"])

                response = fcm_send_bulk_message(api_key=settings.FIREBASE_SERVER_KEY,
                                                 registration_ids=registrationIdList,
                                                 body=body,
                                                 title=subject)
                # add_notification_history(user_object_list, subject, body, response, institute_id,
                #                          history_types.EMAIL)
            except Exception as e:
                print("notification error:" + str(e))
    except Exception as e:
        print("Task Error:" + str(e))
    return True


@shared_task(name="SendPushNotificationTask")
def SendPushNotificationTask(message, title, userlist, FIREBASE_SERVER_KEY):
    print("mass push notification")
    try:
        registrationIdList = []
        for user in userlist:
            if user["firebase_messaging_token"] != "":
                registrationIdList.append(user["firebase_messaging_token"])

        response = fcm_send_bulk_message(api_key=FIREBASE_SERVER_KEY,
                                         registration_ids=registrationIdList,
                                         body=message,
                                         title=title)
    except Exception as e:
        print("notification error:" + str(e))
    return True


def send_mass_html_mail(datatuple, fail_silently=False, user=None, password=None,
                        connection=None):
    """
    Given a datatuple of (subject, text_content, html_content, from_email,
    recipient_list), sends each message to each recipient list. Returns the
    number of emails sent.

    If from_email is None, the DEFAULT_FROM_EMAIL setting is used.
    If auth_user and auth_password are set, they're used to log in.
    If auth_user is None, the EMAIL_HOST_USER setting is used.
    If auth_password is None, the EMAIL_HOST_PASSWORD setting is used.

    """
    connection = connection or get_connection(
        username=user, password=password, fail_silently=fail_silently)
    messages = []
    for subject, text, html, from_email, recipient in datatuple:
        message = EmailMultiAlternatives(subject, text, from_email, recipient)
        message.attach_alternative(html, 'text/html')
        messages.append(message)
    return connection.send_messages(messages)


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

