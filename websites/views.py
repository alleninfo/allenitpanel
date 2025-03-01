from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
import subprocess
from .models import Website, AppStore, AppInstallLog, ActivityLog, TerminalSession
from django.db import models, connection
import os
import psutil
import platform
import time
from django.utils import timezone
from datetime import timedelta, datetime
from django.views.decorators.csrf import csrf_exempt
import json
import pwd
import grp
import shutil
import uuid
import mysql.connector
import pty
import termios
import struct
import select

# Create your views here.

# 存储终端会话
terminal_sessions = {}

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
            'uptime': get_uptime(None)
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
    try:
        # 获取系统启动时间
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        days = int(uptime // (24 * 3600))
        hours = int((uptime % (24 * 3600)) // 3600)
        minutes = int((uptime % 3600) // 60)
        return f"{days}天{hours}小时{minutes}分钟"
    except Exception as e:
        print(f"获取系统运行时间出错: {e}")
        return "未知"

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
    
    websites = Website.objects.all()
    return render(request, 'website_manage/website_manage.html', {'websites': websites})

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
            subprocess.run(['sudo', 'systemctl', action, 'mysqld'], check=True)
        elif service == 'php':
            subprocess.run(['sudo', 'systemctl', action, 'php-fpm'], check=True)

        return JsonResponse({'success': True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def database_manage(request):
    """数据库管理页面"""
    try:
        print("尝试连接 MySQL...")
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        print("MySQL 连接成功")
        
        try:
            with mysql_conn.cursor(dictionary=True) as cursor:
                print("执行数据库查询...")
                # 获取所有数据库
                cursor.execute("""
                    SELECT DISTINCT
                        SCHEMA_NAME as name,
                        DEFAULT_CHARACTER_SET_NAME as charset,
                        NOW() as created_at
                    FROM information_schema.SCHEMATA 
                    WHERE SCHEMA_NAME NOT IN 
                        ('information_schema', 'mysql', 'performance_schema', 'sys', 'allenitpanel')
                    ORDER BY SCHEMA_NAME
                """)
                databases = []
                db_rows = cursor.fetchall()
                print(f"找到 {len(db_rows)} 个数据库")
                
                # 使用集合来存储已处理的数据库名称
                processed_dbs = set()
                
                for row in db_rows:
                    db_name = row['name']
                    # 检查是否已处理过这个数据库
                    if db_name in processed_dbs:
                        continue
                    processed_dbs.add(db_name)
                    
                    print(f"处理数据库: {db_name}")
                    db_info = {
                        'id': db_name,
                        'name': db_name,
                        'charset': row['charset'],
                        'created_at': row['created_at'],
                        'status': True,
                        'size': '0 MB',
                        'username': '',
                        'password': ''
                    }
                    
                    try:
                        # 获取数据库大小
                        cursor.execute("""
                            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size
                            FROM information_schema.tables
                            WHERE table_schema = %s
                            GROUP BY table_schema
                        """, (db_name,))
                        size_result = cursor.fetchone()
                        if size_result and size_result['size']:
                            db_info['size'] = f"{size_result['size']} MB"
                    except Exception as e:
                        print(f"获取数据库 {db_name} 大小时出错: {str(e)}")
                    
                    try:
                        # 获取数据库用户
                        cursor.execute("""
                            SELECT DISTINCT db.User, db.Host
                            FROM mysql.db db
                            WHERE db.Db = %s
                        """, (db_name,))
                        users = cursor.fetchall()
                        
                        if users:
                            # 使用第一个用户的信息
                            first_user = users[0]
                            db_info['username'] = first_user['User']
                            
                            # 获取用户密码（从创建时保存）
                            try:
                                cursor.execute("""
                                    CREATE DATABASE IF NOT EXISTS allenitpanel
                                """)
                                cursor.execute("""
                                    CREATE TABLE IF NOT EXISTS allenitpanel.database_passwords (
                                        db_name VARCHAR(64) PRIMARY KEY,
                                        username VARCHAR(64),
                                        password VARCHAR(255),
                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                    )
                                """)
                                cursor.execute("""
                                    SELECT password 
                                    FROM allenitpanel.database_passwords 
                                    WHERE db_name = %s
                                """, (db_name,))
                                pwd_result = cursor.fetchone()
                                if pwd_result:
                                    db_info['password'] = pwd_result['password']
                                else:
                                    db_info['password'] = '********'  # 默认密码掩码
                            except Exception as e:
                                print(f"获取密码时出错: {str(e)}")
                                db_info['password'] = '********'
                        else:
                            db_info['username'] = '无'
                            db_info['password'] = '无'
                            
                    except Exception as e:
                        print(f"获取数据库 {db_name} 用户信息时出错: {str(e)}")
                        db_info['username'] = '获取失败'
                        db_info['password'] = '获取失败'
                    
                    databases.append(db_info)
                    print(f"已添加数据库信息: {db_info}")

                print(f"成功获取到 {len(databases)} 个数据库的信息")
                return render(request, 'db_manage/database_manage.html', {
                    'databases': databases
                })
                
        except Exception as e:
            print(f"查询数据库信息时出错: {str(e)}")
            raise
        finally:
            mysql_conn.close()
            print("MySQL 连接已关闭")
            
    except Exception as e:
        error_msg = f"获取数据库列表失败：{str(e)}"
        print(error_msg)
        messages.error(request, error_msg)
        return render(request, 'db_manage/database_manage.html', {
            'databases': []
        })


@login_required
def firewall_manage(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'firewalld_manage/firewalld_manage.html')


@login_required
def file_manage(request):
    """文件管理视图"""
    current_path = request.GET.get('path', '/')  # 默认显示根目录
    parent_path = os.path.dirname(current_path) if current_path != '/' else None

    try:
        # 获取目录内容
        items = []
        with os.scandir(current_path) as entries:
            for entry in entries:
                try:
                    stat_info = entry.stat()
                    item = {
                        'name': entry.name,
                        'path': os.path.join(current_path, entry.name),
                        'is_dir': entry.is_dir(),
                        'size': stat_info.st_size if not entry.is_dir() else None,
                        'modified': datetime.fromtimestamp(stat_info.st_mtime),
                        'permissions': oct(stat_info.st_mode)[-4:],  # 获取权限
                        'owner': pwd.getpwuid(stat_info.st_uid).pw_name,  # 获取所有者
                        'group': grp.getgrgid(stat_info.st_gid).gr_name,  # 获取组
                    }
                    items.append(item)
                except (PermissionError, FileNotFoundError):
                    continue

        # 排序：目录在前，文件在后，按名称排序
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

        context = {
            'current_path': current_path,
            'parent_path': parent_path,
            'items': items,
        }
        return render(request, 'file_manage/file_manage.html', context)

    except PermissionError:
        messages.error(request, '权限不足，无法访问该目录')
        return redirect('file_manage')
    except FileNotFoundError:
        messages.error(request, '目录不存在')
        return redirect('file_manage')


@login_required
def terminal_manage(request):
    """终端管理页面"""
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
    
    # 更新应用的实际安装状态
    for app in apps:
        real_status = check_app_installed(app.name)
        if app.is_installed != real_status:
            app.is_installed = real_status
            app.save()
            
            # 记录状态变更
            status_str = "已安装" if real_status else "未安装"
            log_activity(request, 'system', f'检测到应用 {app.name} 状态变更为: {status_str}')
    
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
    """添加新网站"""
    try:
        name = request.POST.get('name')
        domain = request.POST.get('domain')
        port = request.POST.get('port', 80)
        php_version = request.POST.get('php_version')
        ssl = request.POST.get('ssl') == 'on'
        path = f'/www/wwwroot/{domain}'  # 使用域名作为目录名
        
        # 创建网站目录
        os.makedirs(path, exist_ok=True)
        
        # 创建网站记录
        website = Website.objects.create(
            name=name,
            domain=domain,
            port=port,
            php_version=php_version,
            path=path,
            ssl=ssl
        )
        
        # 如果启用了SSL，处理SSL配置
        if ssl:
            ssl_type = request.POST.get('ssl_type')
            if ssl_type == 'lets_encrypt':
                # 处理Let's Encrypt证书
                pass
            elif ssl_type == 'custom':
                # 处理自定义证书
                cert_file = request.FILES.get('cert_file')
                key_file = request.FILES.get('key_file')
                if cert_file and key_file:
                    # 保存证书文件
                    pass
        
        # 创建Nginx配置
        create_nginx_config(website)
        
        return JsonResponse({
            'success': True
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

def create_nginx_config(website):
    """创建Nginx配置文件"""
    config = f"""server {{
    listen {website.port};
    server_name {website.domain};
    root {website.path};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    location ~ \.php$ {{
        fastcgi_pass unix:/var/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}"""

    # 如果启用了SSL，添加SSL配置
    if website.ssl:
        ssl_config = f"""
server {{
    listen 443 ssl;
    server_name {website.domain};
    
    ssl_certificate /etc/letsencrypt/live/{website.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{website.domain}/privkey.pem;
    
    root {website.path};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    location ~ \.php$ {{
        fastcgi_pass unix:/var/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}

server {{
    listen 80;
    server_name {website.domain};
    return 301 https://$server_name$request_uri;
}}"""
        config = ssl_config

    # 保存配置文件 - 修改为CentOS的配置目录
    config_path = f'/etc/nginx/conf.d/{website.domain}.conf'
    
    # 确保目录存在
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)
    
    with open(config_path, 'w') as f:
        f.write(config)

    # 测试并重载Nginx配置
    test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if test_result.returncode == 0:
        subprocess.run(['systemctl', 'reload', 'nginx'])
    else:
        raise Exception(f"Nginx配置测试失败: {test_result.stderr}")

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

@csrf_exempt
def apply_ssl(request):
    if request.method == 'POST':
        try:
            # 获取域名
            domain = request.POST.get('domain')
            verify_method = request.POST.get('verifyMethod')
            
            if not domain:
                return JsonResponse({
                    'status': 'error',
                    'message': '域名不能为空'
                })

            # 检查域名是否已配置SSL
            ssl_config_path = f'/etc/nginx/sites-available/{domain}'
            if os.path.exists(ssl_config_path):
                with open(ssl_config_path, 'r') as f:
                    if 'listen 443 ssl' in f.read():
                        return JsonResponse({
                            'status': 'error',
                            'message': '该域名已配置SSL证书'
                        })

            # 确保网站根目录存在
            web_root = f'/www/wwwroot/{domain}'
            if not os.path.exists(web_root):
                os.makedirs(web_root, exist_ok=True)

            # 构建certbot命令
            if verify_method == 'http':
                cmd = [
                    'certbot', 'certonly', '--webroot',
                    '-w', web_root,
                    '-d', domain,
                    '--non-interactive',
                    '--agree-tos',
                    '--email', 'admin@example.com'  # 需要替换为实际的邮箱
                ]
            else:
                cmd = [
                    'certbot', 'certonly', '--manual',
                    '--preferred-challenges', 'dns',
                    '-d', domain,
                    '--non-interactive',
                    '--agree-tos',
                    '--email', 'admin@example.com'  # 需要替换为实际的邮箱
                ]

            # 执行certbot命令
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if process.returncode == 0:
                # 配置Nginx SSL
                if configure_nginx_ssl(domain):
                    return JsonResponse({
                        'status': 'success',
                        'message': 'SSL证书已成功申请并配置'
                    })
                else:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Nginx配置失败'
                    })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': f'证书申请失败: {process.stderr}'
                })

        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'操作失败: {str(e)}'
            })

    return JsonResponse({
        'status': 'error',
        'message': '不支持的请求方法'
    })

def configure_nginx_ssl(domain):
    """配置Nginx SSL"""
    try:
        cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
        key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'
        
        # 生成SSL配置
        config = f"""
server {{
    listen 443 ssl;
    server_name {domain};
    
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    
    # SSL配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS配置
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    root /www/wwwroot/{domain};
    index index.html index.htm index.php;
    
    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}
    
    location ~ \.php$ {{
        fastcgi_pass unix:/var/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}

server {{
    listen 80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}
"""
        
        # 写入配置文件
        config_path = f'/etc/nginx/sites-available/{domain}'
        with open(config_path, 'w') as f:
            f.write(config)
        
        # 创建符号链接
        enabled_path = f'/etc/nginx/sites-enabled/{domain}'
        if not os.path.exists(enabled_path):
            os.symlink(config_path, enabled_path)
        
        # 测试配置
        test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
        if test_result.returncode == 0:
            # 重启Nginx
            subprocess.run(['systemctl', 'reload', 'nginx'])
            return True
        else:
            print(f"Nginx配置测试失败: {test_result.stderr}")
            return False
            
    except Exception as e:
        print(f"配置Nginx SSL时发生错误: {str(e)}")
        return False

@csrf_exempt
def upload_ssl(request):
    if request.method == 'POST':
        try:
            domain = request.POST.get('domain')
            cert_file = request.FILES.get('certFile')
            key_file = request.FILES.get('keyFile')
            chain_file = request.FILES.get('chainFile')
            
            if not domain:
                return JsonResponse({
                    'status': 'error',
                    'message': '域名不能为空'
                })
                
            if not cert_file or not key_file:
                return JsonResponse({
                    'status': 'error',
                    'message': '请上传证书文件和私钥文件'
                })

            # 创建证书存储目录
            ssl_dir = f'/etc/ssl/private/{domain}'
            os.makedirs(ssl_dir, exist_ok=True)
            
            # 保存证书文件
            cert_path = os.path.join(ssl_dir, f'{domain}.crt')
            key_path = os.path.join(ssl_dir, f'{domain}.key')
            chain_path = os.path.join(ssl_dir, f'{domain}_chain.crt') if chain_file else None
            
            with open(cert_path, 'wb+') as f:
                for chunk in cert_file.chunks():
                    f.write(chunk)
            
            with open(key_path, 'wb+') as f:
                for chunk in key_file.chunks():
                    f.write(chunk)
            
            if chain_file:
                with open(chain_path, 'wb+') as f:
                    for chunk in chain_file.chunks():
                        f.write(chunk)
            
            # 设置适当的文件权限
            os.chmod(cert_path, 0o644)
            os.chmod(key_path, 0o600)
            if chain_path:
                os.chmod(chain_path, 0o644)
            
            # 配置 Nginx SSL
            config = f"""
server {{
    listen 443 ssl;
    server_name {domain};
    
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    {f'ssl_trusted_certificate {chain_path};' if chain_path else ''}
    
    # SSL配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS配置
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    root /www/wwwroot/{domain};
    index index.html index.htm index.php;
    
    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}
    
    location ~ \.php$ {{
        fastcgi_pass unix:/var/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}

server {{
    listen 80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}
"""
            
            # 写入 Nginx 配置
            config_path = f'/etc/nginx/sites-available/{domain}'
            with open(config_path, 'w') as f:
                f.write(config)
            
            # 创建符号链接
            enabled_path = f'/etc/nginx/sites-enabled/{domain}'
            if not os.path.exists(enabled_path):
                os.symlink(config_path, enabled_path)
            
            # 测试 Nginx 配置
            test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if test_result.returncode == 0:
                # 重启 Nginx
                subprocess.run(['systemctl', 'reload', 'nginx'])
                return JsonResponse({
                    'status': 'success',
                    'message': 'SSL证书已成功上传并配置'
                })
            else:
                # 配置测试失败，清理文件
                os.remove(config_path)
                if os.path.exists(enabled_path):
                    os.remove(enabled_path)
                return JsonResponse({
                    'status': 'error',
                    'message': f'Nginx配置测试失败: {test_result.stderr}'
                })
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'上传证书失败: {str(e)}'
            })
    
    return JsonResponse({
        'status': 'error',
        'message': '不支持的请求方法'
    })

def get_file_info(path):
    """获取文件信息"""
    try:
        stat_info = os.stat(path)
        return {
            'size': stat_info.st_size,
            'modified': datetime.fromtimestamp(stat_info.st_mtime),
            'permissions': oct(stat_info.st_mode)[-4:],
            'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
            'group': grp.getgrgid(stat_info.st_gid).gr_name,
        }
    except (PermissionError, FileNotFoundError):
        return None

@csrf_exempt
def upload_file(request):
    """处理文件上传"""
    if request.method == 'POST':
        try:
            upload_path = request.GET.get('path', '/')
            uploaded_file = request.FILES['file']
            file_path = os.path.join(upload_path, uploaded_file.name)
            
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})

def download_file(request):
    """处理文件下载"""
    file_path = request.GET.get('path')
    if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=os.path.basename(file_path))
    return JsonResponse({'status': 'error', 'message': '文件不存在'})

@csrf_exempt
def create_folder(request):
    """创建文件夹"""
    if request.method == 'POST':
        try:
            current_path = request.POST.get('current_path')
            folder_name = request.POST.get('folder_name')
            new_folder_path = os.path.join(current_path, folder_name)
            
            if not os.path.exists(new_folder_path):
                os.makedirs(new_folder_path)
                messages.success(request, '文件夹创建成功')
            else:
                messages.error(request, '文件夹已存在')
        except Exception as e:
            messages.error(request, f'创建文件夹失败：{str(e)}')
        
        return redirect(f'/file_manage/?path={current_path}')
    return redirect('file_manage')

@csrf_exempt
def rename_item(request):
    """重命名文件或文件夹"""
    if request.method == 'POST':
        try:
            old_path = request.POST.get('old_path')
            new_name = request.POST.get('new_name')
            current_path = os.path.dirname(old_path)
            new_path = os.path.join(current_path, new_name)
            
            if not os.path.exists(new_path):
                os.rename(old_path, new_path)
                messages.success(request, '重命名成功')
            else:
                messages.error(request, '目标名称已存在')
        except Exception as e:
            messages.error(request, f'重命名失败：{str(e)}')
        
        return redirect(f'/file_manage/?path={current_path}')
    return redirect('file_manage')

@csrf_exempt
def delete_item(request):
    """删除文件或文件夹"""
    if request.method == 'POST':
        try:
            path = request.POST.get('path')
            current_path = os.path.dirname(path)
            
            if os.path.isdir(path):
                import shutil
                shutil.rmtree(path)
            else:
                os.remove(path)
            messages.success(request, '删除成功')
        except Exception as e:
            messages.error(request, f'删除失败：{str(e)}')
        
        return redirect(f'/file_manage/?path={current_path}')
    return redirect('file_manage')

@csrf_exempt
def create_file(request):
    """创建新文件"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            current_path = data.get('current_path')
            file_name = data.get('file_name')
            file_path = os.path.join(current_path, file_name)
            
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write('')
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'status': 'error', 'message': '文件已存在'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})

def read_file(request):
    """读取文件内容"""
    try:
        file_path = request.GET.get('path')
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            return JsonResponse({'status': 'success', 'content': content})
        return JsonResponse({'status': 'error', 'message': '文件不存在'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@csrf_exempt
def save_file(request):
    """保存文件内容"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            file_path = data.get('path')
            content = data.get('content')
            
            with open(file_path, 'w') as f:
                f.write(content)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})

@csrf_exempt
def paste_items(request):
    """粘贴文件或文件夹"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            items = data.get('items', [])
            action = data.get('action')
            destination = data.get('destination')
            
            for item_path in items:
                item_name = os.path.basename(item_path)
                new_path = os.path.join(destination, item_name)
                
                if action == 'cut':
                    shutil.move(item_path, new_path)
                else:  # copy
                    if os.path.isdir(item_path):
                        shutil.copytree(item_path, new_path)
                    else:
                        shutil.copy2(item_path, new_path)
                        
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})

@csrf_exempt
def batch_delete(request):
    """批量删除文件或文件夹"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            items = data.get('items', [])
            
            for item_path in items:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                    
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})



def check_app_installed(app_name):
    """检查应用是否实际安装在系统中"""
    try:
        if app_name.lower() == 'nginx':
            # 检查 nginx 是否安装并能正常运行
            which_result = subprocess.run(['which', 'nginx'], capture_output=True)
            if which_result.returncode != 0:
                return False
            # 检查服务状态
            status_result = subprocess.run(['systemctl', 'is-active', 'nginx'], capture_output=True, text=True)
            if status_result.stdout.strip() != 'active':
                return False
            # 检查进程
            ps_result = subprocess.run(['pgrep', 'nginx'], capture_output=True)
            return ps_result.returncode == 0
            
        elif app_name.lower() == 'mysql':
            # 检查 mysql 客户端和服务器
            which_result = subprocess.run(['which', 'mysql'], capture_output=True)
            if which_result.returncode != 0:
                return False
            # 检查 mysql/mysqld 服务状态
            for service in ['mysqld', 'mysql']:
                status_result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
                if status_result.stdout.strip() == 'active':
                    # 检查进程
                    ps_result = subprocess.run(['pgrep', 'mysql'], capture_output=True)
                    return ps_result.returncode == 0
            return False
            
        elif app_name.lower() == 'php':
            try:
                # 检查 PHP 命令
                which_php = subprocess.run(['which', 'php'], capture_output=True)
                if which_php.returncode != 0:
                    return False
                
                # 检查可能的PHP-FPM服务名称
                php_fpm_services = ['php-fpm', 'php7.4-fpm', 'php8.0-fpm', 'php8.1-fpm', 'php8.2-fpm', 'php74-php-fpm']
                service_active = False
                
                for service in php_fpm_services:
                    status_result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
                    if status_result.stdout.strip() == 'active':
                        service_active = True
                        break
                
                # 检查 PHP-FPM 进程
                ps_result = subprocess.run(['pgrep', '-f', 'php-fpm'], capture_output=True)
                process_running = ps_result.returncode == 0
                
                # 如果服务正在运行或进程存在，返回True
                if service_active or process_running:
                    return True
                
                # 如果找到php命令，尝试获取PHP版本
                version_result = subprocess.run(['php', '-v'], capture_output=True, text=True)
                if version_result.returncode == 0:
                    return True
                
                return False
                
            except Exception as e:
                print(f"检查PHP状态时出错: {str(e)}")
                return False
            
        elif app_name.lower() == 'redis':
            # 检查 Redis 命令行工具
            which_result = subprocess.run(['which', 'redis-cli'], capture_output=True)
            if which_result.returncode != 0:
                return False
            # 检查 Redis 服务状态
            status_result = subprocess.run(['systemctl', 'is-active', 'redis'], capture_output=True, text=True)
            if status_result.stdout.strip() != 'active':
                return False
            # 检查进程
            ps_result = subprocess.run(['pgrep', 'redis'], capture_output=True)
            return ps_result.returncode == 0
            
        elif app_name.lower() == 'docker':
            # 检查 Docker 命令
            which_result = subprocess.run(['which', 'docker'], capture_output=True)
            if which_result.returncode != 0:
                return False
            # 检查 Docker 服务状态
            status_result = subprocess.run(['systemctl', 'is-active', 'docker'], capture_output=True, text=True)
            if status_result.stdout.strip() != 'active':
                return False
            # 检查进程
            ps_result = subprocess.run(['pgrep', 'docker'], capture_output=True)
            return ps_result.returncode == 0
            
        return False
    except Exception as e:
        print(f"检查应用 {app_name} 状态时出错: {str(e)}")
        return False

def get_php_versions(request):
    """获取系统中已安装的PHP版本"""
    try:
        versions = []
        # 检查常见的PHP-FPM服务
        php_services = [
            'php-fpm',
            'php7.4-fpm',
            'php8.0-fpm',
            'php8.1-fpm',
            'php8.2-fpm',
            'php74-php-fpm'
        ]
        
        for service in php_services:
            status_result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
            if status_result.stdout.strip() == 'active':
                # 从服务名称提取版本号
                if service == 'php-fpm':
                    # 获取默认PHP版本
                    version_result = subprocess.run(['php', '-v'], capture_output=True, text=True)
                    if version_result.returncode == 0:
                        version_line = version_result.stdout.split('\n')[0]
                        version = version_line.split()[1].split('.')[0:2]
                        versions.append(f"{version[0]}.{version[1]}")
                else:
                    # 从服务名称解析版本号
                    version = service.split('-')[0].replace('php', '')
                    if version:
                        versions.append(version)
        
        # 如果没有找到任何版本，尝试直接检查PHP命令
        if not versions:
            version_result = subprocess.run(['php', '-v'], capture_output=True, text=True)
            if version_result.returncode == 0:
                version_line = version_result.stdout.split('\n')[0]
                version = version_line.split('.')[0:2]
                versions.append(f"{version[0]}.{version[1]}")
        
        return JsonResponse({
            'success': True,
            'versions': sorted(list(set(versions)))  # 去重并排序
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["POST"])
def add_database(request):
    """创建新数据库"""
    try:
        name = request.POST.get('name')
        username = request.POST.get('username')
        password = request.POST.get('password')
        access = request.POST.get('access')
        charset = request.POST.get('charset', 'utf8mb4')
        
        # 验证输入
        if not all([name, username, password]):
            return JsonResponse({
                'success': False,
                'error': '请填写所有必填字段'
            })
            
        # 根据访问权限设置host
        host = '%' if access == 'remote' else 'localhost'
        if access == 'specified':
            host = request.POST.get('specified_ip', 'localhost')
        
        # 创建MySQL连接
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        
        try:
            with mysql_conn.cursor() as cursor:
                # 先尝试删除已存在的用户和数据库
                try:
                    cursor.execute(f"DROP USER IF EXISTS '{username}'@'{host}'")
                    cursor.execute(f"DROP DATABASE IF EXISTS `{name}`")
                    mysql_conn.commit()
                except Exception as e:
                    print(f"清理旧数据时出错: {str(e)}")
                
                # 创建数据库
                cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET {charset}")
                
                # 创建用户并授权
                cursor.execute(f"CREATE USER '{username}'@'{host}' IDENTIFIED BY '{password}'")
                cursor.execute(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{username}'@'{host}'")
                
                # 创建allenitpanel数据库和密码表（如果不存在）
                cursor.execute("""
                    CREATE DATABASE IF NOT EXISTS allenitpanel
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS allenitpanel.database_passwords (
                        db_name VARCHAR(64) PRIMARY KEY,
                        username VARCHAR(64),
                        password VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # 保存密码
                cursor.execute("""
                    INSERT INTO allenitpanel.database_passwords (db_name, username, password)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    username = VALUES(username),
                    password = VALUES(password)
                """, (name, username, password))
                
                cursor.execute("FLUSH PRIVILEGES")
                mysql_conn.commit()
                
                return JsonResponse({
                    'success': True,
                    'password': password
                })
                
        finally:
            mysql_conn.close()
                
    except Exception as e:
        print(f"Error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
def manage_database(request, id):
    """管理数据库"""
    try:
        # 创建 MySQL 连接
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        
        try:
            with mysql_conn.cursor(dictionary=True) as cursor:
                # 获取数据库信息
                cursor.execute("SELECT * FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", [id])
                db_info = cursor.fetchone()
                
            if not db_info:
                return JsonResponse({
                    'success': False,
                    'error': '数据库不存在'
                })
                
            return JsonResponse({
                'success': True,
                'database': {
                    'name': db_info['SCHEMA_NAME'],
                    'charset': db_info['DEFAULT_CHARACTER_SET_NAME'],
                    'collation': db_info['DEFAULT_COLLATION_NAME']
                }
            })
        finally:
            mysql_conn.close()
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["POST"])
def backup_database(request, id):
    """备份数据库"""
    try:
        # 创建MySQL连接
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        
        try:
            with mysql_conn.cursor(dictionary=True) as cursor:
                # 检查数据库是否存在
                cursor.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", (id,))
                db = cursor.fetchone()
                
                if not db:
                    return JsonResponse({
                        'success': False,
                        'error': '数据库不存在'
                    })
                
                # 创建备份目录
                backup_dir = '/www/backup/database'
                os.makedirs(backup_dir, exist_ok=True)
                
                # 生成备份文件名
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_file = f"{backup_dir}/{id}_{timestamp}.sql"
                
                # 执行备份命令
                cmd = f"mysqldump -u root -p'oakcdrom' {id} > {backup_file}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(result.stderr)
                
                # 记录活动
                log_activity(request, 'database', f'备份数据库 {id}')
                
                return JsonResponse({
                    'success': True,
                    'file': backup_file
                })
        finally:
            mysql_conn.close()
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["POST"])
def change_database_password(request, id):
    """修改数据库密码"""
    try:
        new_password = request.POST.get('new_password')
        
        if not new_password:
            return JsonResponse({
                'success': False,
                'error': '请输入新密码'
            })
            
        # 获取数据库用户信息
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT USER, HOST FROM mysql.user 
                WHERE USER NOT IN ('root', 'mysql.sys', 'debian-sys-maint', 'mysql.session', 'mysql.infoschema')
                AND HOST != 'localhost'
            """)
            users = cursor.fetchall()
            
            # 修改所有相关用户的密码
            for user, host in users:
                cursor.execute("ALTER USER `%s`@`%s` IDENTIFIED WITH mysql_native_password BY %s", [user, host, new_password])
            
            cursor.execute("FLUSH PRIVILEGES")
            
        return JsonResponse({
            'success': True
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["POST"])
def delete_database(request, id):
    """删除数据库"""
    try:
        # 创建MySQL连接
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        
        try:
            with mysql_conn.cursor(dictionary=True) as cursor:
                # 检查数据库是否存在
                cursor.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", (id,))
                db = cursor.fetchone()
                
                if not db:
                    return JsonResponse({
                        'success': False,
                        'error': '数据库不存在'
                    })
                
                # 获取相关用户
                cursor.execute("""
                    SELECT DISTINCT User, Host 
                    FROM mysql.db 
                    WHERE Db = %s
                """, (id,))
                users = cursor.fetchall()
                
                # 删除数据库
                cursor.execute(f"DROP DATABASE IF EXISTS `{id}`")
                
                # 删除相关用户
                for user in users:
                    cursor.execute(f"DROP USER IF EXISTS '{user['User']}'@'{user['Host']}'")
                
                # 删除密码记录（如果存在）
                try:
                    cursor.execute("DELETE FROM allenitpanel.database_passwords WHERE db_name = %s", (id,))
                except Exception as e:
                    print(f"删除密码记录时出错: {str(e)}")
                
                cursor.execute("FLUSH PRIVILEGES")
                mysql_conn.commit()
                
                # 记录活动
                log_activity(request, 'database', f'删除数据库 {id}')
                
                return JsonResponse({
                    'success': True
                })
                
        finally:
            mysql_conn.close()
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
def edit_website(request, id):
    """编辑网站"""
    try:
        website = Website.objects.get(id=id)
        
        if request.method == 'POST':
            # 获取表单数据
            name = request.POST.get('name')
            domain = request.POST.get('domain')
            port = request.POST.get('port')
            php_version = request.POST.get('php_version')
            ssl = request.POST.get('ssl') == 'on'
            
            # 更新网站信息
            website.name = name
            website.domain = domain
            website.port = port
            website.php_version = php_version
            website.ssl = ssl
            website.save()
            
            # 更新Nginx配置
            create_nginx_config(website)
            
            return JsonResponse({'success': True})
        else:
            # GET请求，返回网站信息
            return render(request, 'website_manage/edit_website.html', {
                'website': website
            })
            
    except Website.DoesNotExist:
        return JsonResponse({'success': False, 'error': '网站不存在'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def website_files(request, id):
    """网站文件管理"""
    try:
        website = Website.objects.get(id=id)
        current_path = request.GET.get('path', website.path)
        
        # 确保路径在网站目录内
        if not current_path.startswith(website.path):
            current_path = website.path
        
        # 处理面包屑导航
        relative_path = current_path[len(website.path):].strip('/')
        path_parts = []
        if relative_path:
            accumulated_path = ''
            parts = relative_path.split('/')
            for part in parts:
                if part:
                    accumulated_path = (accumulated_path + '/' + part).strip('/')
                    path_parts.append({
                        'name': part,
                        'path': accumulated_path
                    })
        
        # 获取父目录路径
        parent_path = os.path.dirname(current_path) if current_path != website.path else None
        
        # 获取目录内容
        items = []
        try:
            with os.scandir(current_path) as entries:
                for entry in entries:
                    stat = entry.stat()
                    items.append({
                        'name': entry.name,
                        'path': os.path.join(current_path, entry.name),
                        'is_dir': entry.is_dir(),
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'permissions': oct(stat.st_mode)[-3:],
                        'owner': pwd.getpwuid(stat.st_uid).pw_name,
                        'group': grp.getgrgid(stat.st_gid).gr_name
                    })
            
            # 排序：目录在前，文件在后，按名称排序
            items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

        except PermissionError:
            messages.error(request, '没有权限访问该目录')
            items = []
        except FileNotFoundError:
            messages.error(request, '目录不存在')
            items = []
        
        context = {
            'website': website,
            'current_path': current_path,
            'parent_path': parent_path,
            'path_parts': path_parts,
            'items': items
        }
        return render(request, 'website_manage/website_files.html', context)
        
    except Website.DoesNotExist:
        messages.error(request, '网站不存在')
        return redirect('website_manage')

def check_service_running(service_name):
    """检查服务是否在运行"""
    try:
        if service_name == 'nginx':
            result = subprocess.run(['systemctl', 'is-active', 'nginx'], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        elif service_name == 'mysql':
            result = subprocess.run(['systemctl', 'is-active', 'mysqld'], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        elif service_name == 'php':
            # 检查php-fpm服务
            result = subprocess.run(['systemctl', 'is-active', 'php-fpm'], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        return False
    except Exception as e:
        print(f"Error checking {service_name} status: {str(e)}")
        return False

@require_http_methods(["GET"])
def get_services_status(request):
    """获取所有服务的状态"""
    status = {
        'nginx': check_service_running('nginx'),
        'mysql': check_service_running('mysql'),
        'php': check_service_running('php')
    }
    return JsonResponse(status)

@require_http_methods(["POST"])
def control_service(request, service_name, action):
    """控制服务的启动、停止、重启等操作"""
    allowed_services = ['nginx', 'mysql', 'php']
    allowed_actions = ['start', 'stop', 'restart', 'reload']
    
    if service_name not in allowed_services:
        return JsonResponse({'success': False, 'error': '不支持的服务'})
    
    if action not in allowed_actions:
        return JsonResponse({'success': False, 'error': '不支持的操作'})
    
    try:
        if service_name == 'php':
            service_name = 'php-fpm'  # 对PHP服务使用php-fpm
            
        cmd = ['systemctl', action, service_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': result.stderr})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def edit_database(request, name):
    """编辑数据库"""
    try:
        # 创建MySQL连接
        mysql_conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="oakcdrom",
            allow_local_infile=True,
            auth_plugin='mysql_native_password'
        )
        
        try:
            with mysql_conn.cursor(dictionary=True) as cursor:
                if request.method == 'POST':
                    # 获取表单数据
                    charset = request.POST.get('charset')
                    access = request.POST.get('access')
                    new_password = request.POST.get('new_password')
                    specified_ip = request.POST.get('specified_ip')
                    
                    # 设置host
                    host = '%' if access == 'remote' else 'localhost'
                    if access == 'specified' and specified_ip:
                        host = specified_ip
                    
                    # 修改数据库字符集
                    cursor.execute(f"ALTER DATABASE `{name}` CHARACTER SET = {charset}")
                    
                    # 如果提供了新密码，修改用户密码
                    if new_password:
                        # 获取数据库用户
                        cursor.execute("""
                            SELECT DISTINCT User, Host 
                            FROM mysql.db 
                            WHERE Db = %s
                        """, (name,))
                        users = cursor.fetchall()
                        
                        for user in users:
                            # 修改用户密码和host
                            cursor.execute(f"ALTER USER '{user['User']}'@'{user['Host']}' IDENTIFIED BY %s", (new_password,))
                            if user['Host'] != host:
                                # 创建新的用户权限
                                cursor.execute(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user['User']}'@'{host}' IDENTIFIED BY %s", (new_password,))
                                # 删除旧的用户
                                cursor.execute(f"DROP USER '{user['User']}'@'{user['Host']}'")
                    
                    mysql_conn.commit()
                    return JsonResponse({'success': True})
                else:
                    # GET请求，获取数据库信息
                    cursor.execute("""
                        SELECT 
                            SCHEMA_NAME as name,
                            DEFAULT_CHARACTER_SET_NAME as charset,
                            NOW() as created_at
                        FROM information_schema.SCHEMATA 
                        WHERE SCHEMA_NAME = %s
                    """, (name,))
                    database = cursor.fetchone()
                    
                    if not database:
                        messages.error(request, '数据库不存在')
                        return redirect('database_manage')
                    
                    # 获取数据库大小
                    cursor.execute("""
                        SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size
                        FROM information_schema.tables
                        WHERE table_schema = %s
                        GROUP BY table_schema
                    """, (name,))
                    size_result = cursor.fetchone()
                    database['size'] = f"{size_result['size'] if size_result else 0} MB"
                    
                    # 获取数据库用户
                    cursor.execute("""
                        SELECT DISTINCT User 
                        FROM mysql.db 
                        WHERE Db = %s
                    """, (name,))
                    users = cursor.fetchall()
                    database['username'] = ', '.join(user['User'] for user in users) if users else '无'
                    
                    # 检查数据库状态
                    database['status'] = True
                    
                    return render(request, 'db_manage/edit_database.html', {
                        'database': database
                    })
        finally:
            mysql_conn.close()
            
    except Exception as e:
        if request.method == 'POST':
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
        messages.error(request, f'获取数据库信息失败：{str(e)}')
        return redirect('database_manage')

@login_required
@require_http_methods(["POST"])
def terminal_init(request):
    """初始化终端会话"""
    try:
        data = json.loads(request.body)
        terminal_id = data.get('terminal_id')
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        
        # 创建伪终端
        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            ['/bin/bash'],
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            universal_newlines=True
        )
        
        # 存储终端会话信息
        terminal_sessions[terminal_id] = {
            'master_fd': master_fd,
            'slave_fd': slave_fd,
            'process': process,
            'output_buffer': [],
            'output_id': 0
        }
        
        # 设置终端大小
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def terminal_input(request):
    """处理终端输入"""
    try:
        data = json.loads(request.body)
        terminal_id = data.get('terminal_id')
        input_data = data.get('input')
        
        if terminal_id in terminal_sessions:
            session = terminal_sessions[terminal_id]
            os.write(session['master_fd'], input_data.encode())
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': '终端会话不存在'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def terminal_resize(request):
    """处理终端大小调整"""
    try:
        data = json.loads(request.body)
        terminal_id = data.get('terminal_id')
        cols = data.get('cols')
        rows = data.get('rows')
        
        if terminal_id in terminal_sessions:
            session = terminal_sessions[terminal_id]
            fcntl.ioctl(session['master_fd'], termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': '终端会话不存在'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def terminal_output(request):
    """获取终端输出"""
    try:
        terminal_id = request.GET.get('terminal_id')
        last_output_id = int(request.GET.get('last_output_id', 0))
        
        if terminal_id in terminal_sessions:
            session = terminal_sessions[terminal_id]
            
            # 检查进程是否还在运行
            if session['process'].poll() is not None:
                del terminal_sessions[terminal_id]
                return JsonResponse({
                    'success': False,
                    'error': '终端会话已结束'
                })
            
            # 读取新的输出
            try:
                while True:
                    r, w, e = select.select([session['master_fd']], [], [], 0)
                    if not r:
                        break
                        
                    output = os.read(session['master_fd'], 1024).decode(errors='ignore')
                    if output:
                        session['output_id'] += 1
                        session['output_buffer'].append({
                            'id': session['output_id'],
                            'data': output
                        })
            except (OSError, IOError):
                pass
            
            # 获取新的输出
            new_output = ''
            new_output_id = last_output_id
            
            for output in session['output_buffer']:
                if output['id'] > last_output_id:
                    new_output += output['data']
                    new_output_id = output['id']
            
            # 清理旧的输出
            session['output_buffer'] = [
                output for output in session['output_buffer']
                if output['id'] > last_output_id - 100  # 保留最近的100条输出
            ]
            
            return JsonResponse({
                'success': True,
                'output': new_output,
                'output_id': new_output_id
            })
        else:
            return JsonResponse({
                'success': False,
                'error': '终端会话不存在'
            })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })



