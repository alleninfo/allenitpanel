from django.db import models
from django.contrib.auth.models import User

class FileShare(models.Model):
    name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=1024)
    share_token = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    expires_at = models.DateTimeField(null=True, blank=True)
    download_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class FileOperation(models.Model):
    OPERATION_TYPES = [
        ('upload', '上传'),
        ('download', '下载'),
        ('delete', '删除'),
        ('rename', '重命名'),
        ('move', '移动'),
        ('copy', '复制'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    operation_type = models.CharField(max_length=20, choices=OPERATION_TYPES)
    file_path = models.CharField(max_length=1024)
    new_path = models.CharField(max_length=1024, blank=True)  # 用于移动/复制操作
    size = models.BigIntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username} - {self.operation_type} - {self.file_path}"
