from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from .models import Website, SSLCertificate, WebsiteBackup, AdditionalDomain
from panel.models import AuditLog
import os
import shutil
from datetime import timezone, timedelta
import subprocess
import re
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@login_required
def website_list(request):
    websites = Website.objects.all().order_by('-created_at')
    return render(request, 'websites/list.html', {'websites': websites})

@login_required
def website_create(request):
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            main_domain = request.POST.get('domain')
            additional_domains = request.POST.getlist('additional_domains')
            port = request.POST.get('port')
            server_type = request.POST.get('server_type')
            php_version = request.POST.get('php_version')
            
            # 创建网站目录
            path = f'/www/wwwroot/{main_domain}'
            os.makedirs(path, exist_ok=True)
            
            # 创建网站记录
            website = Website.objects.create(
                name=name,
                domain=main_domain,
                path=path,
                port=port,
                server_type=server_type,
                php_version=php_version
            )
            
            # 添加额外域名
            for domain in additional_domains:
                if domain and domain != main_domain:
                    AdditionalDomain.objects.create(
                        website=website,
                        domain=domain.strip()
                    )
            
            # 生成服务器配置文件
            try:
                if server_type == 'nginx':
                    generate_nginx_config(website)
                else:
                    generate_apache_config(website)
                
                messages.success(request, '网站创建成功')
            except Exception as e:
                # 如果配置文件生成失败，删除网站记录
                website.delete()
                if os.path.exists(path):
                    shutil.rmtree(path)
                messages.error(request, f'网站创建失败：{str(e)}')
                return redirect('website_list')
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'创建网站 {main_domain}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return redirect('website_list')
        except Exception as e:
            messages.error(request, f'网站创建失败：{str(e)}')
            return redirect('website_list')
    
    # 获取已安装的PHP版本
    php_versions = []
    try:
        output = subprocess.check_output(['php', '-v'], universal_newlines=True)
        version_match = re.search(r'PHP (\d+\.\d+\.\d+)', output)
        if version_match:
            php_versions.append(version_match.group(1))
    except:
        pass
    
    return render(request, 'websites/website_create.html', {
        'php_versions': php_versions
    })

@login_required
def website_detail(request, pk):
    website = get_object_or_404(Website, pk=pk)
    ssl_certs = website.sslcertificate_set.all().order_by('-created_at')
    backups = website.websitebackup_set.all().order_by('-created_at')
    additional_domains = website.additional_domains.all()
    
    context = {
        'website': website,
        'ssl_certs': ssl_certs,
        'backups': backups,
        'additional_domains': additional_domains,
    }
    return render(request, 'websites/detail.html', context)

@login_required
def website_toggle(request, pk):
    website = get_object_or_404(Website, pk=pk)
    status = request.POST.get('status') == 'true'
    
    if status:
        # 启动网站
        if website.server_type == 'nginx':
            os.system(f'systemctl start nginx')
        else:
            os.system(f'systemctl start apache2')
    else:
        # 停止网站
        if website.server_type == 'nginx':
            os.system(f'systemctl stop nginx')
        else:
            os.system(f'systemctl stop apache2')
    
    website.status = status
    website.save()
    
    # 记录操作日志
    action = '启动' if status else '停止'
    AuditLog.objects.create(
        user=request.user,
        action=f'{action}网站 {website.domain}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return JsonResponse({'status': 'success'})

@login_required
@csrf_exempt
@require_http_methods(["POST"])
def website_delete(request, pk):
    try:
        website = get_object_or_404(Website, pk=pk)
        domain = website.domain
        
        # 删除额外域名
        website.additional_domains.all().delete()
        
        # 删除网站文件
        if os.path.exists(website.path):
            try:
                shutil.rmtree(website.path)
            except Exception as e:
                return JsonResponse({
                    'status': 'error',
                    'message': f'删除网站文件失败：{str(e)}'
                })
        
        # 删除配置文件
        config_paths = []
        if website.server_type == 'nginx':
            config_paths.append(f'/etc/nginx/sites-enabled/{website.domain}.conf')
        else:
            config_paths.append(f'/etc/apache2/sites-enabled/{website.domain}.conf')
        
        # 删除所有域名的配置文件
        for domain in website.additional_domains.all():
            if website.server_type == 'nginx':
                config_paths.append(f'/etc/nginx/sites-enabled/{domain.domain}.conf')
            else:
                config_paths.append(f'/etc/apache2/sites-enabled/{domain.domain}.conf')
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    os.remove(config_path)
                except Exception as e:
                    return JsonResponse({
                        'status': 'error',
                        'message': f'删除配置文件失败：{str(e)}'
                    })
        
        # 重新加载服务器配置
        try:
            if website.server_type == 'nginx':
                subprocess.run(['nginx', '-t'], check=True)
                subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
            else:
                subprocess.run(['apache2ctl', 'configtest'], check=True)
                subprocess.run(['systemctl', 'reload', 'apache2'], check=True)
        except subprocess.CalledProcessError as e:
            return JsonResponse({
                'status': 'error',
                'message': f'重新加载服务器配置失败：{str(e)}'
            })
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'删除网站 {domain}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        # 删除网站记录
        website.delete()
        
        return JsonResponse({
            'status': 'success',
            'message': '网站已成功删除'
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'删除网站失败：{str(e)}'
        })

@login_required
def website_ssl(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    if request.method == 'POST':
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        
        if cert_file and key_file:
            # 保存证书文件
            cert = SSLCertificate.objects.create(
                website=website,
                common_name=website.domain,
                issuer='Manual Upload',
                valid_from=timezone.now(),
                valid_to=timezone.now() + timedelta(days=365),
                certificate_file=cert_file,
                private_key_file=key_file
            )
            
            # 更新网站配置
            website.ssl_enabled = True
            website.save()
            
            # 更新服务器配置
            if website.server_type == 'nginx':
                update_nginx_ssl_config(website, cert)
            else:
                update_apache_ssl_config(website, cert)
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'为网站 {website.domain} 配置SSL证书',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'SSL证书配置成功')
            return redirect('website_detail', pk=website.pk)
    
    return render(request, 'websites/ssl.html', {'website': website})

@login_required
def website_config(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    if request.method == 'POST':
        config_content = request.POST.get('config')
        config_path = f'/etc/nginx/sites-enabled/{website.domain}.conf' if website.server_type == 'nginx' else f'/etc/apache2/sites-enabled/{website.domain}.conf'
        
        # 保存配置文件
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        # 重启服务器
        if website.server_type == 'nginx':
            os.system('systemctl reload nginx')
        else:
            os.system('systemctl reload apache2')
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'修改网站 {website.domain} 配置',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, '配置已更新')
        return redirect('website_detail', pk=website.pk)
    
    # 读取当前配置
    config_path = f'/etc/nginx/sites-enabled/{website.domain}.conf' if website.server_type == 'nginx' else f'/etc/apache2/sites-enabled/{website.domain}.conf'
    config_content = ''
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_content = f.read()
    
    return render(request, 'websites/config.html', {
        'website': website,
        'config_content': config_content
    })

@login_required
def website_logs(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    # 读取访问日志
    access_log_path = f'/var/log/nginx/{website.domain}.access.log' if website.server_type == 'nginx' else f'/var/log/apache2/{website.domain}.access.log'
    access_logs = []
    if os.path.exists(access_log_path):
        with open(access_log_path, 'r') as f:
            access_logs = f.readlines()[-1000:]  # 只显示最后1000行
    
    # 读取错误日志
    error_log_path = f'/var/log/nginx/{website.domain}.error.log' if website.server_type == 'nginx' else f'/var/log/apache2/{website.domain}.error.log'
    error_logs = []
    if os.path.exists(error_log_path):
        with open(error_log_path, 'r') as f:
            error_logs = f.readlines()[-1000:]  # 只显示最后1000行
    
    return render(request, 'websites/logs.html', {
        'website': website,
        'access_logs': access_logs,
        'error_logs': error_logs
    })

def generate_nginx_config(website):
    # 确保配置目录存在
    nginx_dir = '/etc/nginx/sites-enabled'
    os.makedirs(nginx_dir, exist_ok=True)
    
    config_path = f'{nginx_dir}/{website.domain}.conf'
    config_content = f"""server {{
    listen {website.port};
    server_name {website.domain};
    
    root {website.path};
    index index.html index.htm index.php;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    
    # PHP-FPM 配置
    location ~ \.php$ {{
        fastcgi_pass unix:/run/php/php{website.php_version}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}

"""

    # 添加额外域名的 server_name
    additional_domains = website.additional_domains.all()
    if additional_domains:
        domain_list = [website.domain] + [d.domain for d in additional_domains]
        config_content = config_content.replace(
            f'server_name {website.domain};',
            f'server_name {" ".join(domain_list)};'
        )
    
    # 写入配置文件
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    # 重新加载 Nginx 配置
    try:
        subprocess.run(['nginx', '-t'], check=True)  # 测试配置
        subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
    except subprocess.CalledProcessError:
        # 如果配置测试失败，删除配置文件
        if os.path.exists(config_path):
            os.remove(config_path)
        raise Exception('Nginx配置测试失败')

def generate_apache_config(website):
    # 确保配置目录存在
    apache_dir = '/etc/apache2/sites-enabled'
    os.makedirs(apache_dir, exist_ok=True)
    
    config_path = f'{apache_dir}/{website.domain}.conf'
    config_content = f"""<VirtualHost *:{website.port}>
    ServerName {website.domain}
    DocumentRoot {website.path}
    
    <Directory {website.path}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # PHP 配置
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php{website.php_version}-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>"""

    # 添加额外域名
    additional_domains = website.additional_domains.all()
    if additional_domains:
        for domain in additional_domains:
            config_content = config_content.replace(
                f'ServerName {website.domain}',
                f'ServerName {website.domain}\n    ServerAlias {domain.domain}'
            )
    
    # 写入配置文件
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    # 重新加载 Apache 配置
    try:
        subprocess.run(['apache2ctl', 'configtest'], check=True)  # 测试配置
        subprocess.run(['systemctl', 'reload', 'apache2'], check=True)
    except subprocess.CalledProcessError:
        # 如果配置测试失败，删除配置文件
        if os.path.exists(config_path):
            os.remove(config_path)
        raise Exception('Apache配置测试失败')

def update_nginx_ssl_config(website, cert):
    """更新Nginx SSL配置"""
    config = f"""server {{
    listen 443 ssl;
    server_name {website.domain};
    root {website.path};
    index index.html index.htm index.php;
    
    ssl_certificate {cert.certificate_file.path};
    ssl_certificate_key {cert.private_key_file.path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    
    location ~ \.php$ {{
        fastcgi_pass unix:/run/php/php{website.php_version}-fpm.sock;
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
    
    config_path = f'/etc/nginx/sites-enabled/{website.domain}.conf'
    with open(config_path, 'w') as f:
        f.write(config)
    
    os.system('systemctl reload nginx')

def update_apache_ssl_config(website, cert):
    """更新Apache SSL配置"""
    config = f"""<VirtualHost *:443>
    ServerName {website.domain}
    DocumentRoot {website.path}
    
    SSLEngine on
    SSLCertificateFile {cert.certificate_file.path}
    SSLCertificateKeyFile {cert.private_key_file.path}
    
    <Directory {website.path}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${{APACHE_LOG_DIR}}/{website.domain}.error.log
    CustomLog ${{APACHE_LOG_DIR}}/{website.domain}.access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName {website.domain}
    Redirect permanent / https://{website.domain}/
</VirtualHost>"""
    
    config_path = f'/etc/apache2/sites-enabled/{website.domain}.conf'
    with open(config_path, 'w') as f:
        f.write(config)
    
    os.system('systemctl reload apache2')
