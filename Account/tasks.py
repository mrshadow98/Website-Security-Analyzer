import datetime
import json

from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template import loader
from fcm_django.fcm import fcm_send_bulk_message
from Analyser.analyzer import AnalyserOutputEncoder, calculate_probability_of_phishing, Analyzer
from Analyser.models import RequestData, Result, Keys
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




@shared_task(name="analyse")
def analyse(scan_id):
    VIRUS_TOTAL_KEY = Keys.objects.get(name="VirusTotal")
    GOOGLE_SAFE_BROWSING_KEY = Keys.objects.get(name="GoogleSafeBrowsing")
    scan = RequestData.objects.get(id=scan_id)
    scan.is_scan_scheduled = False
    scan.is_scan_started = True
    scan.save()
    t1 = datetime.datetime.now()
    analyser = Analyzer(scan.url, VIRUS_TOTAL_KEY.public_key, GOOGLE_SAFE_BROWSING_KEY.public_key)
    t2 = datetime.datetime.now()
    scan.result_calculation_percentage = 10
    scan.save()
    summery = analyser.get_summery()
    t3 = datetime.datetime.now()
    scan.result_calculation_percentage = 12
    scan.save()
    html = analyser.get_html_analysis()
    pp = calculate_probability_of_phishing(summery, html)
    summery["Probability of Phishing"] = pp
    t4 = datetime.datetime.now()
    scan.result_calculation_percentage = 40
    scan.save()
    common = analyser.get_common_analysis()
    t5 = datetime.datetime.now()
    scan.result_calculation_percentage = 55
    scan.save()
    tandd = analyser.get_technology_and_dns_analysis()
    t6 = datetime.datetime.now()
    scan.result_calculation_percentage = 70
    scan.save()
    scan.result_calculation_percentage = 100
    scan.save()
    total_time = (t6 - t1).total_seconds()
    output = {
        'summery': summery, 'html': html, 'common': common, 'tandd': tandd,
        'total_time': total_time
    }
    print(output)
    print(f'Total time taken: {total_time} seconds\n')
    print(f'Percentage of time taken by each function:\n')
    print(f'get_summery: {(t3 - t2).total_seconds() / total_time * 100:.2f}%')
    print(f'get_html_analysis: {(t4 - t3).total_seconds() / total_time * 100:.2f}%')
    print(f'get_common_analysis: {(t5 - t4).total_seconds() / total_time * 100:.2f}%')
    print(f'get_technology_and_dns_analysis: {(t6 - t5).total_seconds() / total_time * 100:.2f}%')
    output_json = json.dumps(output, cls=AnalyserOutputEncoder)
    res = Result(url=scan.url, data=output_json)
    res.save()
    scan.result = res
    scan.is_scan_completed = True
    scan.save()


@shared_task(name="sweep_init")
def sweep_init():
    max_count = 4
    request_qs = RequestData.objects.filter(is_scan_started=True, is_scan_completed=False)
    if request_qs.exists():
        if request_qs.count() < max_count:
            request_scheduled_qs = RequestData.objects.filter(is_scan_scheduled=True)
            how_many = max_count - request_qs.count()
            if request_scheduled_qs.count() > how_many:
                if how_many > 0:
                    for i in range(0, how_many):
                        analyse.delay(request_scheduled_qs[i].id)
    else:
        request_scheduled_qs = RequestData.objects.filter(is_scan_scheduled=True)
        for i in request_scheduled_qs:
            analyse.delay(i.id)


