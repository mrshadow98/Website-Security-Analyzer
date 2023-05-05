from django.contrib import admin

# Register your models here.
from Analyser.models import *

admin.site.register(RequestData)
admin.site.register(Result)
admin.site.register(Keys)
