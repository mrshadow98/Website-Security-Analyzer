import os
from datetime import timedelta

from celery import Celery

# Set the default Django settings module for the 'celery' program.
from celery.schedules import crontab
from datetime import timedelta
from WebsiteSecurityAnalyser import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'WebsiteSecurityAnalyser.settings')

app = Celery('WebsiteSecurityAnalyser', include=[])

app.conf.beat_schedule = {
    'initial_sweep': {
        'task': 'sweep',
        'schedule': 5,
        'relative': True
    }
}

CELERY_TIMEZONE = 'Asia/Kolkata'
# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings')
CELERY_BROKER_URL = 'amqp://guest:guest@localhost:15672/'
# Load task modules from all registered Django apps.
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
BROKER_CONNECTION_RETRY = True
BROKER_CONNECTION_MAX_RETRIES = 0
BROKER_CONNECTION_TIMEOUT = 10120
