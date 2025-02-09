# Generated by Django 4.2.19 on 2025-02-09 14:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Database',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('db_type', models.CharField(choices=[('mysql', 'MySQL'), ('postgresql', 'PostgreSQL'), ('sqlite', 'SQLite')], max_length=20)),
                ('username', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=255)),
                ('host', models.CharField(default='localhost', max_length=255)),
                ('port', models.IntegerField()),
                ('charset', models.CharField(default='utf8mb4', max_length=20)),
                ('status', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='DatabaseUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=255)),
                ('host', models.CharField(default='%', max_length=255)),
                ('privileges', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('database', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='databases.database')),
            ],
        ),
        migrations.CreateModel(
            name='DatabaseImport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.CharField(max_length=255)),
                ('file_size', models.BigIntegerField()),
                ('status', models.CharField(choices=[('pending', '等待中'), ('running', '执行中'), ('success', '成功'), ('failed', '失败')], default='pending', max_length=20)),
                ('clear_database', models.BooleanField(default=False)),
                ('error', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('database', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='databases.database')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='DatabaseBackupSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('storage_type', models.CharField(choices=[('local', '本地存储'), ('ftp', 'FTP服务器'), ('s3', 'Amazon S3')], default='local', max_length=20)),
                ('compression', models.CharField(choices=[('none', '不压缩'), ('gzip', 'GZIP'), ('zip', 'ZIP')], default='gzip', max_length=20)),
                ('encrypt_backup', models.BooleanField(default=False)),
                ('ftp_host', models.CharField(blank=True, max_length=255)),
                ('ftp_username', models.CharField(blank=True, max_length=100)),
                ('ftp_password', models.CharField(blank=True, max_length=100)),
                ('s3_access_key', models.CharField(blank=True, max_length=100)),
                ('s3_secret_key', models.CharField(blank=True, max_length=100)),
                ('s3_bucket', models.CharField(blank=True, max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('database', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='databases.database')),
            ],
        ),
        migrations.CreateModel(
            name='DatabaseBackupSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('schedule_type', models.CharField(choices=[('daily', '每天'), ('weekly', '每周'), ('monthly', '每月')], max_length=20)),
                ('weekday', models.IntegerField(blank=True, null=True)),
                ('day', models.IntegerField(blank=True, null=True)),
                ('time', models.TimeField()),
                ('backup_type', models.CharField(choices=[('full', '完整备份'), ('incremental', '增量备份')], max_length=20)),
                ('keep_backups', models.IntegerField(default=7)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('database', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='databases.database')),
            ],
        ),
        migrations.CreateModel(
            name='DatabaseBackupExecution',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('backup_file', models.FileField(blank=True, null=True, upload_to='backups/databases/')),
                ('status', models.CharField(choices=[('pending', '等待中'), ('running', '执行中'), ('success', '成功'), ('failed', '失败')], default='pending', max_length=20)),
                ('executed_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('duration', models.IntegerField(blank=True, null=True)),
                ('error', models.TextField(blank=True)),
                ('note', models.TextField(blank=True)),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='databases.databasebackupschedule')),
            ],
            options={
                'ordering': ['-executed_at'],
            },
        ),
        migrations.CreateModel(
            name='DatabaseBackup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('backup_file', models.FileField(upload_to='backups/databases/')),
                ('size', models.BigIntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('note', models.TextField(blank=True)),
                ('database', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='databases.database')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
