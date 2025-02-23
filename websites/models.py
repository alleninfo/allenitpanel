from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Website(models.Model):
    name = models.CharField(max_length=100, verbose_name='网站名称')
    domain = models.CharField(max_length=100, verbose_name='域名')
    port = models.IntegerField(default=80, verbose_name='端口')
    php_version = models.CharField(max_length=10, verbose_name='PHP版本')
    path = models.CharField(max_length=255, verbose_name='网站目录')
    ssl = models.BooleanField(default=False, verbose_name='SSL状态')
    status = models.BooleanField(default=True, verbose_name='运行状态')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    class Meta:
        verbose_name = '网站'
        verbose_name_plural = '网站'
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    def get_full_domain(self):
        if self.port == 80:
            return self.domain
        return f"{self.domain}:{self.port}"

class AppStore(models.Model):
    APP_CATEGORIES = [
        ('web', 'Web服务器'),
        ('database', '数据库'),
        ('language', '编程语言'),
        ('cache', '缓存服务'),
        ('tools', '系统工具'),
    ]

    name = models.CharField(max_length=100, verbose_name='应用名称')
    category = models.CharField(max_length=20, choices=APP_CATEGORIES, verbose_name='分类')
    description = models.TextField(verbose_name='应用描述')
    version = models.CharField(max_length=20, verbose_name='版本')
    icon_class = models.CharField(max_length=50, verbose_name='图标类名')
    is_installed = models.BooleanField(default=False, verbose_name='是否已安装')
    install_command = models.TextField(verbose_name='安装命令')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    class Meta:
        verbose_name = '应用'
        verbose_name_plural = '应用'
        ordering = ['category', 'name']

    def __str__(self):
        return self.name

class AppInstallLog(models.Model):
    app = models.ForeignKey(AppStore, on_delete=models.CASCADE, verbose_name='应用')
    status = models.BooleanField(default=False, verbose_name='安装状态')
    output = models.TextField(blank=True, verbose_name='输出信息')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='安装时间')

    class Meta:
        verbose_name = '安装日志'
        verbose_name_plural = '安装日志'
        ordering = ['-created_at']

class ActivityLog(models.Model):
    ACTIVITY_TYPES = (
        ('login', '用户登录'),
        ('logout', '用户登出'),
        ('install', '安装应用'),
        ('uninstall', '卸载应用'),
        ('system', '系统操作'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPES)
    description = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
