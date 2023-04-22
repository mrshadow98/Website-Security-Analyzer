from django.conf.urls import url
from django.urls import path, re_path
from . import views

VERSION = ""

urlpatterns = [
    path("scan_url/", views.scan_url, name=VERSION + "scan_url"),
]
