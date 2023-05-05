from django.core.management import BaseCommand

from Account.models import User
from Analyser.models import Keys


class Command(BaseCommand):

    def handle(self, *args, **options):
        if User.objects.count() == 0:
            username = 'admin'
            phone_no = '9960436653'
            password = 'admin'
            print('Creating account for %s (%s)' % (username, phone_no))
            admin = User.objects.create_superuser(phone_no=phone_no, password=password)
            admin.is_active = True
            admin.is_admin = True
            admin.email = 'admin@gmail.com'
            admin.save()
            Keys(name="GoogleSafeBrowsing").save()
            Keys(name="VirusTotal").save()
        else:
            print('Admin accounts can only be initialized if no Accounts exist')