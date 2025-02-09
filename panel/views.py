from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from .models import AuditLog, UserProfile
from websites.models import Website
from databases.models import Database
import psutil
from django.http import JsonResponse
from .models import Application, ApplicationInstallation
from django.utils import timezone

@login_required
def dashboard(request):
    # 获取系统资源使用情况
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # 获取网站统计数据
    websites = Website.objects.all()
    website_stats = [
        websites.filter(status=True).count(),
        websites.filter(status=False).count(),
        websites.filter(ssl_enabled=True).count(),
        websites.filter(ssl_enabled=False).count(),
    ]
    
    # 获取数据库统计数据
    databases = Database.objects.all()
    database_stats = [
        databases.filter(db_type='mysql').count(),
        databases.filter(db_type='postgresql').count(),
        databases.filter(db_type='sqlite').count(),
    ]
    
    # 获取最近的操作日志
    recent_logs = AuditLog.objects.all()[:10]
    
    context = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'disk_percent': disk.percent,
        'network_rx': '0 B/s',  # 需要实时计算
        'network_tx': '0 B/s',  # 需要实时计算
        'website_stats': website_stats,
        'database_stats': database_stats,
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
                    'versions': []
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
