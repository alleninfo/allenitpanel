from django.db import models

# Create your models here.

class Website(models.Model):
    name = models.CharField(max_length=100)
    domain = models.CharField(max_length=255)
    path = models.CharField(max_length=255)
    port = models.IntegerField()
    server_type = models.CharField(max_length=20, choices=[
        ('nginx', 'Nginx'),
        ('apache', 'Apache'),
    ])
    php_version = models.CharField(max_length=20, null=True, blank=True)
    ssl_enabled = models.BooleanField(default=False)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.domain

class SSLCertificate(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE)
    common_name = models.CharField(max_length=255)
    issuer = models.CharField(max_length=255)
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    certificate_file = models.FileField(upload_to='certificates/')
    private_key_file = models.FileField(upload_to='certificates/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.common_name} ({self.website.domain})"

class WebsiteBackup(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE)
    backup_file = models.FileField(upload_to='backups/websites/')
    size = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.website.domain} - {self.created_at}"
