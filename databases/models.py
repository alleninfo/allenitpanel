from django.db import models

# Create your models here.

class Database(models.Model):
    name = models.CharField(max_length=100)
    db_type = models.CharField(max_length=20, choices=[
        ('mysql', 'MySQL'),
        ('postgresql', 'PostgreSQL'),
        ('sqlite', 'SQLite'),
    ])
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)
    host = models.CharField(max_length=255, default='localhost')
    port = models.IntegerField()
    charset = models.CharField(max_length=20, default='utf8mb4')
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.db_type})"

class DatabaseUser(models.Model):
    database = models.ForeignKey(Database, on_delete=models.CASCADE)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)
    host = models.CharField(max_length=255, default='%')
    privileges = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username}@{self.host}"

class DatabaseBackup(models.Model):
    database = models.ForeignKey(Database, on_delete=models.CASCADE)
    backup_file = models.FileField(upload_to='backups/databases/')
    size = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.database.name} - {self.created_at}"

class DatabaseBackupSchedule(models.Model):
    SCHEDULE_TYPES = [
        ('daily', '每天'),
        ('weekly', '每周'),
        ('monthly', '每月'),
    ]
    
    BACKUP_TYPES = [
        ('full', '完整备份'),
        ('incremental', '增量备份'),
    ]
    
    database = models.ForeignKey(Database, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    schedule_type = models.CharField(max_length=20, choices=SCHEDULE_TYPES)
    weekday = models.IntegerField(null=True, blank=True)  # 0-6, 用于每周
    day = models.IntegerField(null=True, blank=True)  # 1-31, 用于每月
    time = models.TimeField()
    backup_type = models.CharField(max_length=20, choices=BACKUP_TYPES)
    keep_backups = models.IntegerField(default=7)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_schedule_type_display()})"

class DatabaseBackupExecution(models.Model):
    STATUS_CHOICES = [
        ('pending', '等待中'),
        ('running', '执行中'),
        ('success', '成功'),
        ('failed', '失败'),
    ]
    
    schedule = models.ForeignKey(DatabaseBackupSchedule, on_delete=models.CASCADE)
    backup_file = models.FileField(upload_to='backups/databases/', null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    executed_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(null=True, blank=True)  # 执行时长（秒）
    error = models.TextField(blank=True)
    note = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-executed_at']
    
    def __str__(self):
        return f"{self.schedule.name} - {self.executed_at}"

class DatabaseBackupSettings(models.Model):
    STORAGE_TYPES = [
        ('local', '本地存储'),
        ('ftp', 'FTP服务器'),
        ('s3', 'Amazon S3'),
    ]
    
    COMPRESSION_TYPES = [
        ('none', '不压缩'),
        ('gzip', 'GZIP'),
        ('zip', 'ZIP'),
    ]
    
    database = models.OneToOneField(Database, on_delete=models.CASCADE)
    storage_type = models.CharField(max_length=20, choices=STORAGE_TYPES, default='local')
    compression = models.CharField(max_length=20, choices=COMPRESSION_TYPES, default='gzip')
    encrypt_backup = models.BooleanField(default=False)
    
    # FTP设置
    ftp_host = models.CharField(max_length=255, blank=True)
    ftp_username = models.CharField(max_length=100, blank=True)
    ftp_password = models.CharField(max_length=100, blank=True)
    
    # S3设置
    s3_access_key = models.CharField(max_length=100, blank=True)
    s3_secret_key = models.CharField(max_length=100, blank=True)
    s3_bucket = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.database.name} 备份设置"

class DatabaseImport(models.Model):
    STATUS_CHOICES = [
        ('pending', '等待中'),
        ('running', '执行中'),
        ('success', '成功'),
        ('failed', '失败'),
    ]
    
    database = models.ForeignKey(Database, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    clear_database = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.database.name} - {self.file_name} ({self.get_status_display()})"
