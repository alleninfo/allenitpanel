from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from panel.models import AuditLog
from .models import SystemStatus, Process, Service
from .utils import (
    get_system_info, get_cpu_info, get_memory_info, get_disk_info,
    get_network_info, get_process_list, kill_process, get_service_status,
    control_service, get_system_logs, get_system_updates, get_disk_io
)
import json
from datetime import datetime
import os
import subprocess

# Create your views here.

@login_required
def system_status(request):
    """系统状态概览"""
    system_info = get_system_info()
    cpu_info = get_cpu_info()
    memory_info = get_memory_info()
    disk_info = get_disk_info()
    network_info = get_network_info()
    
    # 获取进程列表（只取前50个最占用CPU的进程）
    processes = get_process_list()[:50]
    
    # 获取服务状态
    services = Service.objects.all()
    for service in services:
        service.is_running = get_service_status(service.name)
    
    context = {
        'system_info': system_info,
        'cpu_info': cpu_info,
        'memory_info': memory_info,
        'disk_info': disk_info,
        'network_info': network_info,
        'processes': processes,
        'services': services,
    }
    
    return render(request, 'system/status.html', context)

@login_required
def system_stats(request):
    """获取实时系统资源使用情况"""
    stats = {
        'cpu': get_cpu_info(),
        'memory': get_memory_info(),
        'disk': get_disk_io(),
        'network': get_network_info()['io_stats'],
    }
    return JsonResponse(stats)

@login_required
def kill_process_view(request, pid):
    """结束指定进程"""
    if request.method == 'POST':
        try:
            process = Process.objects.get(pid=pid)
            if kill_process(pid):
                # 记录操作日志
                AuditLog.objects.create(
                    user=request.user,
                    action=f'结束进程 {process.name} (PID: {pid})',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    details=json.dumps({
                        'pid': pid,
                        'name': process.name,
                        'status': 'success'
                    })
                )
                return JsonResponse({'status': 'success'})
            return JsonResponse({'status': 'error', 'message': '无法结束进程'}, status=500)
        except Process.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': '进程不存在'}, status=404)
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def service_control(request, service_id):
    """控制系统服务"""
    if request.method == 'POST':
        try:
            service = Service.objects.get(pk=service_id)
            action = request.POST.get('action')
            
            if action not in ['start', 'stop', 'restart']:
                return JsonResponse({'status': 'error', 'message': '无效的操作'}, status=400)
            
            if control_service(service.name, action):
                # 记录操作日志
                AuditLog.objects.create(
                    user=request.user,
                    action=f'{action} 服务 {service.name}',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    details=json.dumps({
                        'service': service.name,
                        'action': action,
                        'status': 'success'
                    })
                )
                return JsonResponse({'status': 'success'})
            return JsonResponse({'status': 'error', 'message': '操作失败'}, status=500)
        except Service.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': '服务不存在'}, status=404)
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def system_logs_view(request):
    """查看系统日志"""
    log_type = request.GET.get('type', 'system')
    lines = int(request.GET.get('lines', 100))
    logs = get_system_logs(log_type, lines)
    
    return render(request, 'system/logs.html', {
        'logs': logs,
        'log_type': log_type,
        'lines': lines
    })

@login_required
def system_updates_view(request):
    """系统更新检查"""
    updates = get_system_updates()
    
    return render(request, 'system/updates.html', {
        'updates': updates
    })

@login_required
def save_system_status(request):
    """保存系统状态快照"""
    try:
        cpu_info = get_cpu_info()
        memory_info = get_memory_info()
        disk_io = get_disk_io()
        network_info = get_network_info()['io_stats']
        
        status = SystemStatus.objects.create(
            cpu_usage=cpu_info['total_cpu_usage'],
            memory_total=memory_info['total'],
            memory_used=memory_info['used'],
            disk_total=sum(disk['total'] for disk in get_disk_info()),
            disk_used=sum(disk['used'] for disk in get_disk_info()),
            network_rx=network_info['bytes_recv'],
            network_tx=network_info['bytes_sent']
        )
        
        # 保存进程信息
        processes = get_process_list()
        for proc in processes[:100]:  # 只保存前100个进程
            Process.objects.create(
                pid=proc['pid'],
                name=proc['name'],
                cpu_percent=proc['cpu_percent'],
                memory_percent=proc['memory_percent'],
                status=proc['status'],
                created_time=datetime.strptime(proc['create_time'], "%Y-%m-%d %H:%M:%S")
            )
        
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
def network_connections(request):
    """查看网络连接"""
    network_info = get_network_info()
    
    return render(request, 'system/network.html', {
        'network_info': network_info
    })

@login_required
def update_package(request):
    """更新单个软件包"""
    if request.method == 'POST':
        package = request.POST.get('package')
        try:
            if os.name == 'nt':
                # Windows系统使用PowerShell更新
                cmd = ['powershell', 'Install-Package', package, '-Force']
            else:
                # Linux系统更新
                if os.path.exists('/usr/bin/apt'):
                    cmd = ['apt', 'install', '-y', package]
                elif os.path.exists('/usr/bin/dnf'):
                    cmd = ['dnf', 'update', '-y', package]
                else:
                    cmd = ['yum', 'update', '-y', package]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # 记录操作日志
                AuditLog.objects.create(
                    user=request.user,
                    action=f'更新软件包 {package}',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    details=json.dumps({
                        'package': package,
                        'status': 'success',
                        'output': result.stdout
                    })
                )
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': result.stderr or '更新失败'
                }, status=500)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def update_all(request):
    """更新所有软件包"""
    if request.method == 'POST':
        try:
            if os.name == 'nt':
                # Windows系统使用PowerShell更新
                cmd = ['powershell', 'Update-Package', '-Force']
            else:
                # Linux系统更新
                if os.path.exists('/usr/bin/apt'):
                    cmd = ['apt', 'upgrade', '-y']
                elif os.path.exists('/usr/bin/dnf'):
                    cmd = ['dnf', 'upgrade', '-y']
                else:
                    cmd = ['yum', 'upgrade', '-y']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # 记录操作日志
                AuditLog.objects.create(
                    user=request.user,
                    action='更新所有软件包',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    details=json.dumps({
                        'status': 'success',
                        'output': result.stdout
                    })
                )
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': result.stderr or '更新失败'
                }, status=500)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)
