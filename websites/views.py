from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Website, AdditionalDomain
from .forms import WebsiteForm, AdditionalDomainForm
from panel.models import AuditLog, SystemConfig
import os
import shutil
import subprocess
from .utils import get_installed_php_versions
from django.db import connection  # 添加这个导入
from django.http import JsonResponse
from panel.models import ApplicationInstallation, Application
import re
from django.views.decorators.http import require_POST
from django.core.files.storage import FileSystemStorage
from OpenSSL import crypto  # 替换 import OpenSSL
import datetime
from django.utils import timezone



def setup_nginx_and_www_user():
    """设置 Nginx 配置并创建 www 用户"""
    try:
        # 创建 www 组和用户
        os.system('groupadd -f www')
        os.system('useradd -r -g www -s /sbin/nologin www 2>/dev/null || true')
        
        # 修改 Nginx 配置文件
        nginx_conf = '/etc/nginx/nginx.conf'
        
        # 读取当前配置
        with open(nginx_conf, 'r') as f:
            config_lines = f.readlines()
        
        # 处理配置文件
        new_config = []
        user_set = False
        
        # 检查第一个非空行和注释行
        for line in config_lines:
            line = line.strip()
            if not user_set and line and not line.startswith('#'):
                if line.startswith('user '):
                    new_config.append('user www;\n')
                    user_set = True
                else:
                    new_config.append('user www;\n')
                    new_config.append(line + '\n')
                    user_set = True
                continue
            new_config.append(line + '\n')
        
        # 确保配置文件以 } 结尾
        last_line = new_config[-1].strip()
        if last_line and last_line != '}':
            new_config.append('}\n')
        
        # 写回配置文件
        with open(nginx_conf, 'w') as f:
            f.writelines(new_config)
        
        # 设置目录权限
        os.system('chown -R www:www /www/wwwroot')
        os.system('chmod -R 755 /www/wwwroot')
        os.system('chown -R www:www /www/wwwlogs')
        os.system('chmod -R 755 /www/wwwlogs')
        
        # 测试 Nginx 配置
        test_result = os.system('nginx -t')
        if test_result == 0:
            os.system('systemctl restart nginx')
            return True
        else:
            # 如果测试失败，还原配置文件
            with open(nginx_conf, 'w') as f:
                f.writelines(config_lines)
            return False
            
    except Exception as e:
        print(f"设置 Nginx 和 www 用户时出错: {str(e)}")
        return False

# def setup_php_fpm(version, domain):
#     """设置 PHP-FPM 配置"""
#     version_num = version.replace('.', '')
#     port = f'90{version_num}'  # 例如：9074, 9080
    
#     # 修改 PHP-FPM 配置文件路径
#     fpm_config_dir = f'/etc/php/php-fpm.d'
#     fpm_config_file = os.path.join(fpm_config_dir, 'www.conf')
    
#     if os.path.exists(fpm_config_file):
#         backup_file = f'{fpm_config_file}.backup'
#         if not os.path.exists(backup_file):
#             shutil.copy2(fpm_config_file, backup_file)
    
#     # 修改 PHP-FPM 配置，使用 TCP 端口监听
#     fpm_config = f"""[www]
# user = www
# group = www
# listen = 127.0.0.1:{port}
# listen.owner = www
# listen.group = www
# listen.mode = 0660
# listen.allowed_clients = 127.0.0.1

# pm = dynamic
# pm.max_children = 50
# pm.start_servers = 5
# pm.min_spare_servers = 5
# pm.max_spare_servers = 35
# pm.max_requests = 1000

# php_admin_value[error_log] = /www/wwwlogs/php{version_num}_error.log
# php_admin_flag[log_errors] = on
# php_admin_value[upload_max_filesize] = 32M

# ; 添加打开目录的权限
# security.limit_extensions = .php .php3 .php4 .php5 .php7 .php8
# php_admin_value[open_basedir] = /www/wwwroot/{domain}/:/tmp/:/proc/
# """
    
#     os.makedirs(fpm_config_dir, exist_ok=True)
    
#     with open(fpm_config_file, 'w') as f:
#         f.write(fpm_config)
    
#     # 确保 PHP-FPM 目录权限正确
#     os.system(f'chown -R www:www {fpm_config_dir}')
#     os.system(f'chmod -R 755 {fpm_config_dir}')
    
#     # 重启 PHP-FPM 服务
#     os.system(f'systemctl restart php{version_num}-fpm')
    
#     return port

@login_required
def website_list(request):
    websites = Website.objects.all()
    return render(request, 'websites/list.html', {'websites': websites})

@login_required
def website_create(request):
    if request.method == 'POST':
        form = WebsiteForm(request.POST)
        if form.is_valid():
            website = form.save(commit=False)
            website.user = request.user
            website.php_version = form.cleaned_data['php_version']
            
            # 处理 SSL 配置
            ssl_provider = form.cleaned_data['ssl_provider']
            if ssl_provider != 'none':
                website.ssl_enabled = True
                if ssl_provider == 'cloudflare':
                    # Cloudflare SSL 配置路径
                    website.ssl_certificate_path = f'/etc/nginx/ssl/{website.domain}/cloudflare.crt'
                    website.ssl_key_path = f'/etc/nginx/ssl/{website.domain}/cloudflare.key'
                elif ssl_provider == 'letsencrypt':
                    # Let's Encrypt SSL 配置路径
                    website.ssl_certificate_path = f'/etc/letsencrypt/live/{website.domain}/fullchain.pem'
                    website.ssl_key_path = f'/etc/letsencrypt/live/{website.domain}/privkey.pem'
            
            website.save()
            
            # 创建网站目录
            path = os.path.join('/www/wwwroot', website.domain)
            os.makedirs(path, exist_ok=True)
            
            # 如果启用了 SSL，创建 SSL 证书目录
            if website.ssl_enabled and ssl_provider == 'cloudflare':
                ssl_dir = os.path.dirname(website.ssl_certificate_path)
                os.makedirs(ssl_dir, exist_ok=True)
            
            # 创建默认首页
            index_path = os.path.join(path, 'index.html')
            with open(index_path, 'w') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Welcome to {0}</title>
</head>
<body>
    <h1>Welcome to {1}</h1>
</body>
</html>""".format(website.domain, website.domain))
            
            # 创建 Nginx 配置
            nginx_config = f"""server {{
    listen {website.port};
    listen [::]:{website.port};
"""
            
            if website.ssl_enabled:
                nginx_config += f"""    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate {website.ssl_certificate_path};
    ssl_certificate_key {website.ssl_key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    # 添加 HSTS 策略
    add_header Strict-Transport-Security "max-age=31536000" always;
"""
            
            nginx_config += f"""    server_name {website.domain};
    root /www/wwwroot/{website.domain};
    
    index index.php index.html index.htm;
    
    access_log  /www/wwwlogs/{website.domain}.log;
    error_log  /www/wwwlogs/{website.domain}.error.log;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
"""

            if website.php_version and website.php_version != 'none':
                nginx_config += f"""
    location ~ \.php$ {{
        fastcgi_pass unix:/tmp/php-cgi-{website.php_version}.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
"""

            nginx_config += """
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ {
        expires      30d;
    }

    location ~ .*\.(js|css)?$ {
        expires      12h;
    }
}"""

            if website.ssl_enabled:
                # 添加 HTTP 到 HTTPS 的重定向
                nginx_config += f"""

server {{
    listen 80;
    listen [::]:80;
    server_name {website.domain};
    return 301 https://$server_name$request_uri;
}}"""

            nginx_path = f'/etc/nginx/conf.d/{website.domain}.conf'
            with open(nginx_path, 'w') as f:
                f.write(nginx_config)
            
            Website.objects.filter(id=website.id).update(
                path=path,
                nginx_config_path=nginx_path
            )
            
            # 重启 Nginx
            subprocess.run(['systemctl', 'reload', 'nginx'])
            
            messages.success(request, '网站创建成功')
            return redirect('website_list')
    else:
        form = WebsiteForm()
    
    context = {
        'form': form,
        'action': '创建网站',
        'button_text': '创建',
    }
    return render(request, 'websites/form.html', context)

def get_certificate_info(cert_path):
    """获取证书详细信息"""
    try:
        # 检查证书文件是否存在
        if not os.path.exists(cert_path):
            return {
                'error': '证书文件不存在',
                'status': 'error',
                'not_before': None,
                'not_after': None,
                'days_remaining': 0,
                'has_expired': True,
                'issuer': {'CN': '未知'},
                'subject': {'CN': '未知'},
                'alt_names': []
            }

        with open(cert_path) as f:
            cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        
        # 获取证书信息
        not_after = datetime.datetime.strptime(
            cert.get_notAfter().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        ).replace(tzinfo=timezone.utc)
        
        not_before = datetime.datetime.strptime(
            cert.get_notBefore().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        ).replace(tzinfo=timezone.utc)
        
        # 获取证书域名
        alt_names = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                alt_names = str(ext).split(',')
                alt_names = [name.strip().split(':')[1] for name in alt_names]

        # 转换证书信息为字符串
        issuer_dict = {}
        for key, value in cert.get_issuer().get_components():
            issuer_dict[key.decode('utf-8')] = value.decode('utf-8')
        
        subject_dict = {}
        for key, value in cert.get_subject().get_components():
            subject_dict[key.decode('utf-8')] = value.decode('utf-8')
        
        return {
            'status': 'valid',
            'issuer': issuer_dict,
            'subject': subject_dict,
            'not_before': not_before,
            'not_after': not_after,
            'alt_names': alt_names,
            'serial_number': cert.get_serial_number(),
            'has_expired': cert.has_expired(),
            'days_remaining': (not_after - timezone.now()).days
        }
    except Exception as e:
        print(f"证书解析错误: {str(e)}")  # 添加错误日志
        return {
            'error': f'证书解析错误: {str(e)}',
            'status': 'error',
            'not_before': None,
            'not_after': None,
            'days_remaining': 0,
            'has_expired': True,
            'issuer': {'CN': '未知'},
            'subject': {'CN': '未知'},
            'alt_names': []
        }

@login_required
def website_edit(request, pk):
    website = get_object_or_404(Website, pk=pk)
    cert_info = None
    
    # 获取证书信息
    if website.ssl_enabled and website.ssl_certificate_path:
        cert_info = get_certificate_info(website.ssl_certificate_path)
        
        # 如果证书文件不存在，更新网站状态
        if cert_info.get('status') == 'error':
            website.ssl_enabled = False
            website.ssl_provider = 'none'
            website.ssl_certificate_path = None
            website.ssl_key_path = None
            website.save()
    
    if request.method == 'POST':
        form = WebsiteForm(request.POST, instance=website)
        if form.is_valid():
            website = form.save(commit=False)
            
            # 处理 SSL 配置
            ssl_provider = form.cleaned_data['ssl_provider']
            old_ssl_enabled = website.ssl_enabled
            
            if ssl_provider != 'none':
                website.ssl_enabled = True
                if ssl_provider == 'cloudflare':
                    # Cloudflare SSL 配置路径
                    website.ssl_certificate_path = f'/etc/nginx/ssl/{website.domain}/cloudflare.crt'
                    website.ssl_key_path = f'/etc/nginx/ssl/{website.domain}/cloudflare.key'
                    # 创建 SSL 证书目录
                    ssl_dir = os.path.dirname(website.ssl_certificate_path)
                    os.makedirs(ssl_dir, exist_ok=True)
                elif ssl_provider == 'letsencrypt':
                    # Let's Encrypt SSL 配置路径
                    website.ssl_certificate_path = f'/etc/letsencrypt/live/{website.domain}/fullchain.pem'
                    website.ssl_key_path = f'/etc/letsencrypt/live/{website.domain}/privkey.pem'
            else:
                website.ssl_enabled = False
                website.ssl_certificate_path = None
                website.ssl_key_path = None
            
            website.save()
            
            # 如果 SSL 状态发生变化，需要更新 Nginx 配置
            if old_ssl_enabled != website.ssl_enabled:
                # 重新生成 Nginx 配置（这里需要复制上面的 Nginx 配置生成代码）
                nginx_config = f"""server {{
    listen {website.port};
    listen [::]:{website.port};
"""
            
                if website.ssl_enabled:
                    nginx_config += f"""    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate {website.ssl_certificate_path};
    ssl_certificate_key {website.ssl_key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    # 添加 HSTS 策略
    add_header Strict-Transport-Security "max-age=31536000" always;
"""
            
                nginx_config += f"""    server_name {website.domain};
    root /www/wwwroot/{website.domain};
    
    index index.php index.html index.htm;
    
    access_log  /www/wwwlogs/{website.domain}.log;
    error_log  /www/wwwlogs/{website.domain}.error.log;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
"""

                if website.php_version and website.php_version != 'none':
                    nginx_config += f"""
    location ~ \.php$ {{
        fastcgi_pass unix:/tmp/php-cgi-{website.php_version}.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
"""

                nginx_config += """
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ {
        expires      30d;
    }

    location ~ .*\.(js|css)?$ {
        expires      12h;
    }
}"""

                if website.ssl_enabled:
                    # 添加 HTTP 到 HTTPS 的重定向
                    nginx_config += f"""

server {{
    listen 80;
    listen [::]:80;
    server_name {website.domain};
    return 301 https://$server_name$request_uri;
}}"""

                nginx_path = f'/etc/nginx/conf.d/{website.domain}.conf'
                with open(nginx_path, 'w') as f:
                    f.write(nginx_config)
                
                # 重启 Nginx
                subprocess.run(['systemctl', 'reload', 'nginx'])
            
            messages.success(request, '网站更新成功')
            return redirect('website_list')
    else:
        form = WebsiteForm(instance=website)
    
    context = {
        'form': form,
        'website': website,
        'cert_info': cert_info,
        'action': f'编辑网站: {website.name}',
        'button_text': '保存',
    }
    return render(request, 'websites/form.html', context)

@login_required
def website_delete(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    if request.method == 'POST':
        # 删除网站目录
        try:
            shutil.rmtree(website.path)
        except Exception as e:
            messages.error(request, f'删除网站目录失败: {str(e)}')
            return redirect('website_list')
        
        # 记录审计日志
        AuditLog.objects.create(
            user=request.user,
            action=f'删除网站: {website.name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        website.delete()
        return redirect('website_list')
    
    return render(request, 'websites/delete.html', {'website': website})

@login_required
def website_toggle(request, pk):
    website = get_object_or_404(Website, pk=pk)
    website.status = not website.status
    website.save()
    
    # 记录审计日志
    AuditLog.objects.create(
        user=request.user,
        action=f'{"启用" if website.status else "停用"}网站: {website.name}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    messages.success(request, f'网站已{"启用" if website.status else "停用"}')
    return redirect('website_list')

@login_required
def domain_add(request, website_pk):
    website = get_object_or_404(Website, pk=website_pk)
    if request.method == 'POST':
        form = AdditionalDomainForm(request.POST)
        if form.is_valid():
            domain = form.save(commit=False)
            domain.website = website
            domain.save()
            
            # 记录审计日志
            AuditLog.objects.create(
                user=request.user,
                action=f'添加域名 {domain.domain} 到网站: {website.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '域名添加成功')
            return redirect('website_list')
    else:
        form = AdditionalDomainForm()
    
    return render(request, 'websites/domain_form.html', {
        'form': form,
        'website': website
    })

@login_required
def domain_delete(request, pk):
    domain = get_object_or_404(AdditionalDomain, pk=pk)
    website = domain.website
    
    if request.method == 'POST':
        # 记录审计日志
        AuditLog.objects.create(
            user=request.user,
            action=f'删除附加域名: {domain.domain} (网站: {website.name})',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        domain.delete()
        messages.success(request, '域名删除成功')
        return redirect('website_list')
    
    return redirect('website_list')

@login_required
def website_mysql_status(request, pk):
    website = get_object_or_404(Website, pk=pk)
    return JsonResponse({
        'mysql_status': website.mysql_status,
    })

@login_required
def website_form(request, pk=None):
    website = None
    if pk:
        website = get_object_or_404(Website, pk=pk)
    
    if request.method == 'POST':
        form = WebsiteForm(request.POST, instance=website)
        if form.is_valid():
            website = form.save(commit=False)
            website.php_version = request.POST.get('php_version', '')
            website.save()
            messages.success(request, '保存成功')
            return redirect('website_list')
    else:
        form = WebsiteForm(instance=website)

    # 从 ApplicationInstallation 获取已安装的 PHP 版本
    php_versions = ApplicationInstallation.objects.filter(
        application__name__startswith='PHP',
        status='installed'
    ).values_list(
        'application__version', 
        flat=True
    )
    
    # 排序版本号
    php_versions = sorted(php_versions)
    
    context = {
        'form': form,
        'php_versions': php_versions,
        'website': website,
    }
    
    return render(request, 'websites/form.html', context)

@require_POST
@login_required
def website_ssl_renew(request, pk):
    website = get_object_or_404(Website, pk=pk)
    try:
        # 使用 certbot 续期证书
        result = subprocess.run([
            'certbot', 'renew', 
            '--cert-name', website.domain,
            '--non-interactive'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # 记录审计日志
            AuditLog.objects.create(
                user=request.user,
                action=f'续期网站 SSL 证书: {website.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return JsonResponse({'success': True})
        else:
            return JsonResponse({
                'success': False, 
                'error': result.stderr
            })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@require_POST
@login_required
def website_ssl_revoke(request, pk):
    website = get_object_or_404(Website, pk=pk)
    try:
        # 使用 certbot 吊销证书
        result = subprocess.run([
            'certbot', 'revoke',
            '--cert-path', website.ssl_certificate_path,
            '--non-interactive'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # 更新网站 SSL 状态
            website.ssl_enabled = False
            website.ssl_provider = 'none'
            website.ssl_certificate_path = None
            website.ssl_key_path = None
            website.save()
            
            # 记录审计日志
            AuditLog.objects.create(
                user=request.user,
                action=f'吊销网站 SSL 证书: {website.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return JsonResponse({'success': True})
        else:
            return JsonResponse({
                'success': False,
                'error': result.stderr
            })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })
@require_POST
@login_required
def website_ssl_apply(request, pk):
    website = get_object_or_404(Website, pk=pk)
    provider = request.POST.get('provider')
    validation = request.POST.get('validation')
    
    try:
        if provider == 'letsencrypt':
            # 确保网站目录存在
            os.makedirs(website.path, exist_ok=True)
            
            # 处理 Let's Encrypt 证书申请
            if validation == 'http':
                result = subprocess.run([
                    'certbot', 'certonly',
                    '--webroot',
                    '--webroot-path', website.path,
                    '-d', website.domain,
                    '--non-interactive',
                    '--agree-tos',
                    '--email', request.user.email,
                    '--force-renewal'  # 强制更新
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    cert_path = f'/etc/letsencrypt/live/{website.domain}/fullchain.pem'
                    key_path = f'/etc/letsencrypt/live/{website.domain}/privkey.pem'
                    
                    # 检查证书文件是否存在
                    if os.path.exists(cert_path) and os.path.exists(key_path):
                        website.ssl_enabled = True
                        website.ssl_provider = 'letsencrypt'
                        website.ssl_certificate_path = cert_path
                        website.ssl_key_path = key_path
                        website.save()
                        return JsonResponse({'success': True})
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': '证书申请成功但文件未找到'
                        })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f'证书申请失败：{result.stderr}'
                    })
            
            # ... 其余代码保持不变 ...
            
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': '不支持的证书提供商'})

@require_POST
@login_required
def website_ssl_upload(request, pk):
    website = get_object_or_404(Website, pk=pk)
    try:
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        
        if not cert_file or not key_file:
            return JsonResponse({'success': False, 'error': '请上传证书文件和私钥文件'})
        
        # 保存证书文件
        ssl_dir = f'/etc/nginx/ssl/{website.domain}'
        os.makedirs(ssl_dir, exist_ok=True)
        
        fs = FileSystemStorage(location=ssl_dir)
        cert_path = fs.save('cloudflare.crt', cert_file)
        key_path = fs.save('cloudflare.key', key_file)
        
        website.ssl_enabled = True
        website.ssl_provider = 'cloudflare'
        website.ssl_certificate_path = os.path.join(ssl_dir, cert_path)
        website.ssl_key_path = os.path.join(ssl_dir, key_path)
        website.save()
        
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def website_ssl_dns_records(request, pk):
    website = get_object_or_404(Website, pk=pk)
    try:
        # 使用 certbot 的 manual 模式获取 DNS 记录信息
        result = subprocess.run([
            'certbot', '--dry-run', 'certonly', '--manual',
            '--preferred-challenges', 'dns',
            '-d', website.domain,
            '--manual-public-ip-logging-ok',
            '--agree-tos',
            '-m', request.user.email,
            '--force-interactive'  # 强制显示验证信息
        ], capture_output=True, text=True)
        
        # 从输出中提取 DNS 验证信息
        output = result.stdout + result.stderr
        txt_record = None
        domain = None
        
        # 查找 DNS 验证信息
        for line in output.split('\n'):
            if '_acme-challenge.' in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    domain = parts[0]
                    txt_record = parts[1]
                break
        
        if domain and txt_record:
            dns_info = {
                'domain': domain,
                'type': 'TXT',
                'name': '_acme-challenge',
                'value': txt_record,
                'instructions': f'''
请在您的域名解析服务商添加以下 DNS 记录：

记录类型：TXT
主机记录：_acme-challenge
记录值：{txt_record}

等待 DNS 记录生效后（通常需要几分钟到几小时），再点击申请证书按钮。
您可以使用以下命令验证 DNS 记录是否生效：

dig -t txt _acme-challenge.{website.domain}

或者使用在线 DNS 查询工具：
https://toolbox.googleapps.com/apps/dig/#TXT/_acme-challenge.{website.domain}
'''
            }
            return JsonResponse({'success': True, 'records': dns_info})
        else:
            return JsonResponse({
                'success': False, 
                'error': '无法获取 DNS 验证记录，请稍后重试'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'获取 DNS 记录失败：{str(e)}'
        })

