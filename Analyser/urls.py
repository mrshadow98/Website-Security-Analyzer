from django.conf.urls import url
from django.urls import path, re_path
from . import views

VERSION = ""

urlpatterns = [
    path("scan_url/", views.scan_url, name=VERSION + "scan_url"),
    url(r'^scan_url/(?P<pk>[0-9]+)/$', views.scan_url_detail, name='scan_url_detail'),  # GET, delete
]
