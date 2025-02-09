from django.db import models

# Create your models here.

class SystemStatus(models.Model):
    cpu_usage = models.FloatField()
    memory_total = models.BigIntegerField()
    memory_used = models.BigIntegerField()
    disk_total = models.BigIntegerField()
    disk_used = models.BigIntegerField()
    network_rx = models.BigIntegerField()
    network_tx = models.BigIntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

class Process(models.Model):
    pid = models.IntegerField()
    name = models.CharField(max_length=100)
    cpu_percent = models.FloatField()
    memory_percent = models.FloatField()
    status = models.CharField(max_length=20)
    created_time = models.DateTimeField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-cpu_percent']

class Service(models.Model):
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=20)
    port = models.IntegerField(null=True, blank=True)
    auto_start = models.BooleanField(default=True)
    description = models.TextField(blank=True)
    last_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
