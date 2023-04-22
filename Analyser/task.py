from celery import shared_task

from Analyser.models import RequestData


max_count = 4


@shared_task(name="analyse")
def analyse(scan_id):
    scan = RequestData.objects.get(id=scan_id)
    scan.is_scan_scheduled = False
    scan.is_scan_started = True
    scan.save()


@shared_task(name="sweep")
def sweep_check():
    request_qs = RequestData.objects.filter(is_scan_started=True)
    if request_qs.exists():
        if request_qs.count() < max_count:
            request_scheduled_qs = RequestData.objects.filter(is_scan_scheduled=True)
            how_many = max_count - request_qs.count()
            if how_many > 0:
                for i in range[0:how_many]:
                    analyse.delay(request_scheduled_qs[i].id)
