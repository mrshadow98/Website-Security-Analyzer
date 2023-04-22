#!/bin/sh
python3 manage.py wait_for_db
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py initadmin
rm /var/run/celery/w1.pid
rm /var/run/celery/beat.pid
celery multi start w1 -A WebsiteSecurityAnalyser --pidfile=/var/run/celery/%n.pid --logfile=/var/log/celery/%n%I.log --loglevel=ERROR --time-limit=0
celery -A WebsiteSecurityAnalyser beat --pidfile=/var/run/celery/beat.pid --logfile=/var/log/celery/beat.log --loglevel=INFO --detach
python3 manage.py runserver 0.0.0.0:5050