from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from .models import AuditLog, UserProfile
from databases.models import Database
from websites.models import Website
import psutil
from django.http import JsonResponse
from .models import Application, ApplicationInstallation
from django.utils import timezone
import os
import time
import subprocess

class NetworkMonitor:
    _last_bytes = None
    _last_time = None

    @classmethod
    def get_network_speed(cls):
        if cls._last_bytes is None:
            # 首次运行，初始化数据
            cls._last_bytes = psutil.net_io_counters()
            cls._last_time = time.time()
            return {'rx': '0 B/s', 'tx': '0 B/s'}

        current_bytes = psutil.net_io_counters()
        current_time = time.time()

        # 计算时间差
        time_delta = current_time - cls._last_time

        # 计算速度（字节/秒）
        rx_speed = (current_bytes.bytes_recv - cls._last_bytes.bytes_recv) / time_delta
        tx_speed = (current_bytes.bytes_sent - cls._last_bytes.bytes_sent) / time_delta

        # 更新历史数据
        cls._last_bytes = current_bytes
        cls._last_time = current_time

        # 转换单位
        def format_speed(speed):
            units = ['B/s', 'KB/s', 'MB/s', 'GB/s']
            unit_index = 0
            while speed >= 1024 and unit_index < len(units) - 1:
                speed /= 1024
                unit_index += 1
            return f"{speed:.1f} {units[unit_index]}"

        return {
            'rx': format_speed(rx_speed),
            'tx': format_speed(tx_speed)
        }

@login_required
def dashboard(request):
    # 获取系统资源使用情况
    cpu_percent = psutil.cpu_percent()
    cpu_cores = psutil.cpu_count()  # 获取CPU核心数

    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    total_memory = f"{round(memory.total / (1024.0 * 1024 * 1024), 1)}GB"  # 转换为GB并保留一位小数
    
    
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent
    total_disk = f"{round(disk.total / (1024.0 * 1024 * 1024), 1)}GB"  # 转换为GB并保留一位小数
    

    
    # 改进服务状态检测
    def get_service_status(service_name):
        if os.name == 'nt':  # Windows
            try:
                service = psutil.win_service_get(service_name)
                return 'running' if service.status() == 'running' else 'stopped'
            except:
                return 'stopped'
        else:  # Linux
            service_map = {
                'php-fpm': ['php-fpm', 'php7.4-fpm', 'php8.0-fpm', 'php8.1-fpm', 'php8.2-fpm'],  # 常见的PHP-FPM服务名
                'nginx': ['nginx'],
                'mysql': ['mysql', 'mysqld', 'mariadb']  # 包括MariaDB
            }
            
            # 获取可能的服务名列表
            possible_services = service_map.get(service_name, [service_name])
            
            for service in possible_services:
                try:
                    # 使用systemctl命令检查服务状态
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout.strip() == 'active':
                        return 'running'
                        
                    # 如果systemctl不可用，尝试使用service命令
                    result = subprocess.run(
                        ['service', service, 'status'],
                        capture_output=True,
                        text=True
                    )
                    if 'running' in result.stdout.lower():
                        return 'running'
                except:
                    continue
                    
                try:
                    # 对于nginx和php-fpm，还可以通过进程名检查
                    if service_name in ['nginx', 'php-fpm']:
                        for proc in psutil.process_iter(['name']):
                            if service_name in proc.info['name'].lower():
                                return 'running'
                except:
                    pass
                    
                # 特别处理MySQL
                if service_name == 'mysql':
                    try:
                        for proc in psutil.process_iter(['name']):
                            if any(x in proc.info['name'].lower() for x in ['mysql', 'mysqld', 'mariadb']):
                                return 'running'
                    except:
                        pass
            
            return 'stopped'
    
    # 获取最近的操作日志，并确保时间是本地时间
    recent_logs = AuditLog.objects.all().order_by('-created_at')[:10]
    for log in recent_logs:
        # 确保时间是aware的（包含时区信息）
        if timezone.is_naive(log.created_at):
            log.created_at = timezone.make_aware(log.created_at)
        # 转换为本地时间
        log.created_at = timezone.localtime(log.created_at)
    
    # 获取网络速度
    network_speed = NetworkMonitor.get_network_speed()
    
    context = {
        'cpu_percent': cpu_percent,
        'cpu_cores': cpu_cores,
        'memory_percent': memory_percent,
        'total_memory': total_memory,
        'disk_percent': disk_percent,
        'total_disk': total_disk,
        'php_status': get_service_status('php-fpm'),
        'nginx_status': get_service_status('nginx'),
        'mysql_status': get_service_status('mysql'),
        'network_rx': network_speed['rx'],
        'network_tx': network_speed['tx'],
        'recent_logs': recent_logs,
    }
    return render(request, 'panel/dashboard.html', context)

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                AuditLog.objects.create(
                    user=user,
                    action='登录系统',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})

@login_required
def logout_view(request):
    AuditLog.objects.create(
        user=request.user,
        action='退出系统',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    logout(request)
    return redirect('login')

@login_required
def profile(request):
    if request.method == 'POST':
        # 处理个人信息更新
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.email = request.POST.get('email', user.email)
        
        # 如果提供了新密码
        new_password = request.POST.get('new_password')
        if new_password:
            user.set_password(new_password)
        
        user.save()
        messages.success(request, '个人信息已更新')
        return redirect('profile')
    
    return render(request, 'panel/profile.html')

@login_required
def app_store(request):
    """应用商店主页"""
    categories = Application.CATEGORY_CHOICES
    os_versions = Application.OS_CHOICES
    
    # 获取筛选参数
    category = request.GET.get('category')
    os_version = request.GET.get('os')
    search = request.GET.get('search')
    
    # 查询应用列表
    applications = Application.objects.all()
    if category:
        applications = applications.filter(category=category)
    if os_version:
        applications = applications.filter(os_version=os_version)
    if search:
        applications = applications.filter(name__icontains=search)
    
    # 获取已安装应用的信息
    installed_apps = ApplicationInstallation.objects.select_related('application').filter(
        user=request.user
    ).exclude(status='failed').order_by('-started_at')
    
    # 创建已安装应用ID集合
    installed_app_ids = set(inst.application.id for inst in installed_apps)
    
    # 按分类和名称分组应用
    apps_by_category = {}
    for cat, cat_name in categories:
        # 获取该分类下的所有应用
        cat_apps = applications.filter(category=cat)
        # 按应用名称分组
        grouped_apps = {}
        for app in cat_apps:
            if app.name not in grouped_apps:
                grouped_apps[app.name] = {
                    'name': app.name,
                    'description': app.description,
                    'category': app.category,
                    'icon': app.icon,
                    'homepage': app.homepage,
                    'versions': [],
                    'installation_status': app.id in installed_app_ids
                }
            # 添加版本信息
            grouped_apps[app.name]['versions'].append({
                'id': app.id,
                'version': app.version,
                'os_version': app.os_version,
                'os_display': app.get_os_version_display()
            })
        # 将分组后的应用添加到分类字典中
        apps_by_category[cat_name] = grouped_apps.values()
    
    context = {
        'categories': categories,
        'os_versions': os_versions,
        'apps_by_category': apps_by_category,
        'selected_category': category,
        'selected_os': os_version,
        'search_query': search,
        'installed_apps': installed_apps,
    }
    return render(request, 'panel/app_store.html', context)

@login_required
def app_install(request, app_id):
    """安装应用"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '仅支持POST请求'}, status=405)
        
    app = get_object_or_404(Application, pk=app_id)
    
    # 创建安装记录
    installation = ApplicationInstallation.objects.create(
        application=app,
        user=request.user,
        status='installing'
    )
    
    # 记录审计日志
    AuditLog.objects.create(
        user=request.user,
        action=f'开始安装 {app.name} {app.version}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    # 启动安装进程
    try:
        # 创建临时脚本文件
        import tempfile
        import subprocess
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script_file:
            script_file.write(app.install_script)
            script_path = script_file.name
        
        # 设置脚本权限
        os.chmod(script_path, 0o755)
        
        # 异步执行安装脚本
        process = subprocess.Popen(
            [script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        
        # 保存进程ID
        installation.pid = process.pid
        installation.save()
        
        # 启动后台任务监控安装进度
        from threading import Thread
        def monitor_installation():
            try:
                stdout, stderr = process.communicate()
                if process.returncode == 0:
                    installation.status = 'success'
                    installation.completed_at = timezone.now()
                else:
                    installation.status = 'failed'
                    installation.error_message = stderr.decode()
                installation.save()
                
                # 清理临时文件
                os.unlink(script_path)
                
                # 记录安装完成日志
                AuditLog.objects.create(
                    user=request.user,
                    action=f'完成安装 {app.name} {app.version} - {"成功" if process.returncode == 0 else "失败"}',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
            except Exception as e:
                installation.status = 'failed'
                installation.error_message = str(e)
                installation.save()
        
        Thread(target=monitor_installation).start()
        
    except Exception as e:
        installation.status = 'failed'
        installation.error_message = str(e)
        installation.save()
        return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({
        'status': 'success',
        'installation_id': installation.id
    })

@login_required
def app_install_status(request, installation_id):
    """获取安装状态"""
    installation = get_object_or_404(ApplicationInstallation, pk=installation_id)
    return JsonResponse({
        'status': installation.status,
        'error_message': installation.error_message,
        'completed_at': installation.completed_at,
    })

@login_required
def app_uninstall(request, app_id, installation_id):
    """卸载应用"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '仅支持POST请求'}, status=405)
    
    app = get_object_or_404(Application, pk=app_id)
    installation = get_object_or_404(ApplicationInstallation, pk=installation_id, user=request.user)
    
    if not app.uninstall_script:
        return JsonResponse({'status': 'error', 'message': '该应用不支持卸载'}, status=400)
    
    # 记录审计日志
    AuditLog.objects.create(
        user=request.user,
        action=f'卸载应用 {app.name} {app.version}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    try:
        # 创建临时脚本文件
        import tempfile
        import subprocess
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script_file:
            script_file.write(app.uninstall_script)
            script_path = script_file.name
        
        # 设置脚本权限
        os.chmod(script_path, 0o755)
        
        # 执行卸载脚本
        process = subprocess.run(
            [script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True
        )
        
        if process.returncode == 0:
            # 删除安装记录
            installation.delete()
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({
                'status': 'error',
                'message': f'卸载失败: {process.stderr}'
            }, status=500)
            
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'卸载过程中发生错误: {str(e)}'
        }, status=500)
    finally:
        # 清理临时文件
        if 'script_path' in locals():
            try:
                os.unlink(script_path)
            except:
                pass

# 添加一个API端点用于获取实时网络速度
@login_required
def get_network_stats(request):
    network_speed = NetworkMonitor.get_network_speed()
    return JsonResponse(network_speed)

# 添加管理员权限检查
def is_admin(user):
    return user.is_superuser

# 服务控制视图函数
@login_required
@user_passes_test(is_admin)  # 只允许管理员操作
def service_control(request, service_name, action):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': '仅支持POST请求'}, status=405)
    
    # 服务名称标准化映射
    service_map = {
        'php': {
            'names': ['php-fpm', 'php7.4-fpm', 'php8.0-fpm', 'php8.1-fpm', 'php8.2-fpm'],
            'display': 'PHP-FPM'
        },
        'nginx': {
            'names': ['nginx'],
            'display': 'Nginx'
        },
        'mysql': {
            'names': ['mysql', 'mysqld', 'mariadb'],
            'display': 'MySQL'
        }
    }
    
    # 验证服务名称
    if service_name not in service_map:
        return JsonResponse({'success': False, 'message': '无效的服务名称'}, status=400)
    
    # 验证操作类型
    valid_actions = {'restart', 'stop', 'reload'}
    if action not in valid_actions:
        return JsonResponse({'success': False, 'message': '无效的操作类型'}, status=400)
    
    def execute_service_command(service, cmd):
        try:
            # 首先尝试使用 systemctl
            result = subprocess.run(
                ['sudo', 'systemctl', cmd, service],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, "操作成功"
            
            # 如果 systemctl 失败，尝试使用 service 命令
            result = subprocess.run(
                ['sudo', 'service', service, cmd],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, "操作成功"
            
            return False, f"执行命令失败: {result.stderr}"
        except Exception as e:
            return False, f"执行出错: {str(e)}"
    
    # 获取可能的服务名称列表
    possible_services = service_map[service_name]['names']
    service_display_name = service_map[service_name]['display']
    
    # 执行操作
    for service in possible_services:
        success, message = execute_service_command(service, action)
        if success:
            # 记录审计日志
            action_map = {
                'restart': '重启',
                'stop': '停止',
                'reload': '重载'
            }
            try:
                AuditLog.objects.create(
                    user=request.user,
                    action=f'{action_map[action]}服务 {service_display_name}',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
            except:
                pass  # 如果审计日志创建失败，不影响主要功能
                
            return JsonResponse({
                'success': True, 
                'message': f'{service_display_name}服务{action_map[action]}成功'
            })
    
    return JsonResponse({
        'success': False,
        'message': f'{service_display_name}服务操作失败，请检查服务状态'
    }, status=500)
