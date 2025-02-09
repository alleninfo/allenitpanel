from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import subprocess
import os

# Create your views here.

@login_required
def terminal(request):
    """终端页面"""
    # 获取当前用户和主机名
    username = request.user.username
    hostname = os.uname().nodename
    return render(request, 'terminal/index.html', {
        'username': username,
        'hostname': hostname
    })

@login_required
def execute_command(request):
    """执行命令"""
    if request.method == 'POST':
        command = request.POST.get('command')
        try:
            # 获取当前工作目录
            cwd = subprocess.check_output('pwd', shell=True, text=True).strip()
            # 执行命令
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, cwd=cwd)
            # 如果命令是 cd，则需要更新工作目录
            if command.strip().startswith('cd '):
                try:
                    os.chdir(command.strip()[3:])
                    cwd = os.getcwd()
                except:
                    pass
            
            return JsonResponse({
                'status': 'success',
                'output': result.stdout,
                'error': result.stderr,
                'cwd': cwd
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'error': str(e)
            })
