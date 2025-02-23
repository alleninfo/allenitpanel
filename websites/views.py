from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import subprocess
from .models import Website, AppStore, AppInstallLog, ActivityLog
from django.db import models
import os
import psutil
import platform
import time
from django.utils import timezone
from datetime import timedelta

# Create your views here.



def get_service_status():
    # 这里添加获取服务状态的逻辑
    return {
        'nginx': {
            'status': 'running',  # or 'stopped'
            'ports': '80, 443',
        },
        'mysql': {
            'status': 'running',
            'port': '3306',
        },
        'php': {
            'status': 'running',
            'version': '7.4',
        }
    }

def get_system_info():
    # CPU信息
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    cpu_used = round(cpu_count * cpu_percent / 100, 1)
    
    # 内存信息
    memory = psutil.virtual_memory()
    memory_total = bytes_to_human(memory.total)
    memory_used = bytes_to_human(memory.used)
    memory_percent = memory.percent
    
    # 磁盘信息
    disk = psutil.disk_usage('/')
    disk_total = bytes_to_human(disk.total)
    disk_used = bytes_to_human(disk.used)
    disk_percent = disk.percent
    
    # 网络信息
    net_io = psutil.net_io_counters()
    net_speed = get_network_speed()
    
    # 计算网络使用百分比（基于最大1Gbps）
    max_speed = 1024 * 1024 * 1024  # 1 Gbps in bytes
    current_speed_bytes = net_io.bytes_sent + net_io.bytes_recv
    network_percent = min((current_speed_bytes / max_speed) * 100, 100)
    
    return {
        'cpu': {
            'percent': cpu_percent,
            'total_cores': cpu_count,
            'used_cores': cpu_used,
            'info': platform.processor()
        },
        'memory': {
            'total': memory_total,
            'used': memory_used,
            'percent': memory_percent
        },
        'disk': {
            'total': disk_total,
            'used': disk_used,
            'percent': disk_percent
        },
        'network': {
            'speed': net_speed,
            'usage_percent': round(network_percent, 2),
            'sent': bytes_to_human(net_io.bytes_sent),
            'received': bytes_to_human(net_io.bytes_recv)
        },
        'system': {
            'os_type': get_os_type(),
            'os_version': get_os_version(),
            'kernel': platform.release(),
            'uptime': get_uptime(timezone.now())
        }
    }

def bytes_to_human(bytes_value):
    """转换字节为人类可读格式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} PB"

def bytes_to_kb(bytes_value):
    """转换字节为KB，并保留两位小数"""
    return f"{bytes_value / 1024:.2f} KB/S"

def get_os_type():
    """获取操作系统类型"""
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('NAME='):
                    return line.split('=')[1].strip().strip('"')
    return platform.system()

def get_os_version():
    """获取操作系统版本"""
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('VERSION_ID='):
                    return line.split('=')[1].strip().strip('"')
    return platform.version()

def get_uptime(boot_time):
    """计算系统运行时间"""
    uptime = timezone.now() - boot_time
    days = uptime.days
    hours = uptime.seconds // 3600
    minutes = (uptime.seconds % 3600) // 60
    return f"{days}天{hours}小时{minutes}分钟"

def get_network_speed():
    """获取网络速度"""
    # 第一次获取网络数据
    net_io1 = psutil.net_io_counters()
    time.sleep(1)  # 等待1秒
    # 第二次获取网络数据
    net_io2 = psutil.net_io_counters()
    
    # 计算每秒发送和接收的字节数
    bytes_sent = net_io2.bytes_sent - net_io1.bytes_sent
    bytes_recv = net_io2.bytes_recv - net_io1.bytes_recv
    
    return {
        'sent': bytes_to_kb(bytes_sent),
        'received': bytes_to_kb(bytes_recv)
    }

@login_required
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    system_info = get_system_info()
    # 获取最近7天的活动记录
    recent_activities = ActivityLog.objects.filter(
        created_at__gte=timezone.now() - timedelta(days=7)
    )[:10]  # 最近10条记录

    return render(request, 'dashboard.html', {
        'system_info': system_info,
        'recent_activities': recent_activities
    })



def login(request):
    error_message = None
    username = ''
    
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)  # 使用重命名后的 auth_login
                log_activity(request, 'login', f'用户 {user.username} 登录成功')
                return redirect('dashboard')
            else:
                error_message = '用户名或密码错误，请重试！'
        else:
            error_message = '请输入用户名和密码！'
    
    return render(request, 'login.html', {
        'error_message': error_message,
        'username': username
    })


def logout(request):
    if request.user.is_authenticated:
        log_activity(request, 'logout', f'用户 {request.user.username} 登出')
    auth_logout(request)  # 使用重命名后的 auth_logout
    return redirect('login')

@login_required
def website_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'website_manage/website_manage.html')

@login_required


@require_http_methods(["POST"])
def control_service(request, service, action):
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse({'success': False, 'error': '权限不足'})

    allowed_services = ['nginx', 'mysql', 'php']
    allowed_actions = ['reload', 'restart', 'stop']

    if service not in allowed_services or action not in allowed_actions:
        return JsonResponse({'success': False, 'error': '非法操作'})

    try:
        if service == 'nginx':
            if action == 'reload':
                subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], check=True)
            else:
                subprocess.run(['sudo', 'systemctl', action, 'nginx'], check=True)
        elif service == 'mysql':
            subprocess.run(['sudo', 'systemctl', action, 'mysql'], check=True)
        elif service == 'php':
            subprocess.run(['sudo', 'systemctl', action, 'php7.4-fpm'], check=True)

        return JsonResponse({'success': True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def database_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'db_manage/database_manage.html')


@login_required
def firewall_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'firewalld_manage/firewalld_manage.html')


@login_required
def file_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'file_manage/file_manage.html')


@login_required
def terminal_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'terminal_manage/terminal_manage.html')


@login_required
def cron_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'cron_manage/cron_manage.html')


@login_required
def app_store(request):
    """应用商店主页"""
    apps = AppStore.objects.all()
    categories = AppStore.APP_CATEGORIES
    return render(request, 'app_store/app_store.html', {
        'apps': apps,
        'categories': categories
    })

@login_required
@require_http_methods(["POST"])
def install_app(request, app_id):
    """安装应用"""
    try:
        app = AppStore.objects.get(id=app_id)
        
        # 检查是否已安装
        if app.is_installed:
            return JsonResponse({
                'success': False,
                'error': '应用已安装'
            })

        # 执行安装命令
        process = subprocess.Popen(
            app.install_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        # 记录安装结果
        success = process.returncode == 0
        output = stdout.decode() if success else stderr.decode()
        
        AppInstallLog.objects.create(
            app=app,
            status=success,
            output=output
        )

        if success:
            app.is_installed = True
            app.save()
            
        log_activity(request, 'install', f'安装应用 {app.name}')
        
        return JsonResponse({
            'success': success,
            'error': None if success else output
        })

    except AppStore.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': '应用不存在'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["POST"])
def uninstall_app(request, app_id):
    """卸载应用"""
    try:
        app = AppStore.objects.get(id=app_id)
        
        if not app.is_installed:
            return JsonResponse({
                'success': False,
                'error': '应用未安装'
            })

        # 这里添加卸载命令的执行逻辑
        # ...

        app.is_installed = False
        app.save()
        
        log_activity(request, 'uninstall', f'卸载应用 {app.name}')
        
        return JsonResponse({
            'success': True
        })

    except AppStore.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': '应用不存在'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
def get_install_logs(request, app_id):
    """获取应用安装日志"""
    try:
        logs = AppInstallLog.objects.filter(app_id=app_id).order_by('-created_at')[:10]
        return JsonResponse({
            'success': True,
            'logs': [{
                'status': log.status,
                'output': log.output,
                'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for log in logs]
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
def search_apps(request):
    """搜索应用"""
    query = request.GET.get('q', '')
    apps = AppStore.objects.filter(
        models.Q(name__icontains=query) |
        models.Q(description__icontains=query)
    )
    return JsonResponse({
        'success': True,
        'apps': [{
            'id': app.id,
            'name': app.name,
            'category': app.get_category_display(),
            'description': app.description,
            'version': app.version,
            'icon_class': app.icon_class,
            'is_installed': app.is_installed
        } for app in apps]
    })

def website_list(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    websites = Website.objects.all()
    return render(request, 'website_manage/website_manage.html', {'websites': websites})

@require_http_methods(["POST"])
def add_website(request):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': '请先登录'})
    
    try:
        # 处理添加网站的逻辑
        name = request.POST.get('name')
        domain = request.POST.get('domain')
        port = request.POST.get('port')
        php_version = request.POST.get('php_version')
        path = request.POST.get('path')
        ssl = request.POST.get('ssl') == 'on'
        
        # 创建网站
        Website.objects.create(
            name=name,
            domain=domain,
            port=port,
            php_version=php_version,
            path=path,
            ssl=ssl
        )
        
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@require_http_methods(["POST"])
def restart_website(request, id):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': '请先登录'})
    
    try:
        website = Website.objects.get(id=id)
        # 处理重启网站的逻辑
        return JsonResponse({'success': True})
    except Website.DoesNotExist:
        return JsonResponse({'success': False, 'error': '网站不存在'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@require_http_methods(["POST"])
def delete_website(request, id):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': '请先登录'})
    
    try:
        website = Website.objects.get(id=id)
        website.delete()
        return JsonResponse({'success': True})
    except Website.DoesNotExist:
        return JsonResponse({'success': False, 'error': '网站不存在'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def system_info_api(request):
    """API endpoint for system information"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    system_info = get_system_info()
    return JsonResponse(system_info)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def log_activity(request, activity_type, description):
    ActivityLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        activity_type=activity_type,
        description=description,
        ip_address=get_client_ip(request)
    )









