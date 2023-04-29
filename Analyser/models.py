from django.db import models

# Create your models here.
from Account.models import User


class Result(models.Model):
    url = models.CharField(max_length=255)
    data = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.url) + "-"+str(self.id)


class RequestData(models.Model):
    url = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    result_calculation_seconds = models.IntegerField(default=70)
    result_calculation_percentage = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    is_scan_started = models.BooleanField(default=False)
    is_scan_scheduled = models.BooleanField(default=True)
    is_scan_completed = models.BooleanField(default=False)
    result = models.ForeignKey(Result, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.url) + "-"+str(self.user.username)
