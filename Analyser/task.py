import datetime
import json

from celery import shared_task

from Analyser.analyser import Analyser, AnalyserOutputEncoder, calculate_probability_of_phishing
from Analyser.models import RequestData, Result, Keys

max_count = 4


@shared_task(name="analyse")
def analyse(scan_id):
    VIRUS_TOTAL_KEY = Keys.objects.get(name="VirusTotal")
    GOOGLE_SAFE_BROWSING_KEY = Keys.objects.get(name="GoogleSafeBrowsing")
    scan = RequestData.objects.get(id=scan_id)
    scan.is_scan_scheduled = False
    scan.is_scan_started = True
    scan.save()
    t1 = datetime.datetime.now()
    analyser = Analyser(scan.url, VIRUS_TOTAL_KEY.public_key, GOOGLE_SAFE_BROWSING_KEY.public_key)
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


@shared_task(name="sweep")
def sweep_check():
    request_qs = RequestData.objects.filter(is_scan_started=True, is_scan_completed=False)
    if request_qs.exists():
        if request_qs.count() < max_count:
            request_scheduled_qs = RequestData.objects.filter(is_scan_scheduled=True)
            how_many = max_count - request_qs.count()
            if how_many > 0:
                for i in range[0:how_many]:
                    analyse.delay(request_scheduled_qs[i].id)
