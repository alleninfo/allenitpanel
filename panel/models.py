from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    def __str__(self):
        return self.user.username

class SystemSettings(models.Model):
    key = models.CharField(max_length=50, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.key

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} - {self.action} - {self.timestamp}"

class Application(models.Model):
    """应用商店应用"""
    CATEGORY_CHOICES = [
        ('web', 'Web服务器'),
        ('database', '数据库'),
        ('cache', '缓存服务'),
        ('language', '编程语言'),
        ('tool', '管理工具'),
    ]

    OS_CHOICES = [
        ('centos8', 'CentOS 8'),
        ('centos9', 'CentOS 9'),
    ]

    name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField()
    os_version = models.CharField(max_length=20, choices=OS_CHOICES)
    install_script = models.TextField()
    uninstall_script = models.TextField(blank=True)
    icon = models.ImageField(upload_to='app_icons/', blank=True)
    homepage = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('name', 'version', 'os_version')
        ordering = ['name', '-version']

    def __str__(self):
        return f"{self.name} {self.version} ({self.get_os_version_display()})"

class ApplicationInstallation(models.Model):
    """应用安装记录"""
    STATUS_CHOICES = [
        ('pending', '等待安装'),
        ('installing', '安装中'),
        ('success', '安装成功'),
        ('failed', '安装失败'),
    ]

    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    install_path = models.CharField(max_length=255, blank=True)
    port = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"{self.application} - {self.get_status_display()}"
