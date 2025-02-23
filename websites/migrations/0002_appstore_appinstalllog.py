# Generated by Django 4.2.19 on 2025-02-23 03:24

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('websites', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AppStore',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='应用名称')),
                ('category', models.CharField(choices=[('web', 'Web服务器'), ('database', '数据库'), ('language', '编程语言'), ('cache', '缓存服务'), ('tools', '系统工具')], max_length=20, verbose_name='分类')),
                ('description', models.TextField(verbose_name='应用描述')),
                ('version', models.CharField(max_length=20, verbose_name='版本')),
                ('icon_class', models.CharField(max_length=50, verbose_name='图标类名')),
                ('is_installed', models.BooleanField(default=False, verbose_name='是否已安装')),
                ('install_command', models.TextField(verbose_name='安装命令')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
            ],
            options={
                'verbose_name': '应用',
                'verbose_name_plural': '应用',
                'ordering': ['category', 'name'],
            },
        ),
        migrations.CreateModel(
            name='AppInstallLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.BooleanField(default=False, verbose_name='安装状态')),
                ('output', models.TextField(blank=True, verbose_name='输出信息')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='安装时间')),
                ('app', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='websites.appstore', verbose_name='应用')),
            ],
            options={
                'verbose_name': '安装日志',
                'verbose_name_plural': '安装日志',
                'ordering': ['-created_at'],
            },
        ),
    ]
