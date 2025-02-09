from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from .models import Website, SSLCertificate, WebsiteBackup
from panel.models import AuditLog
import os
import shutil
from datetime import timezone, timedelta

@login_required
def website_list(request):
    websites = Website.objects.all().order_by('-created_at')
    return render(request, 'websites/list.html', {'websites': websites})

@login_required
def website_create(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        domain = request.POST.get('domain')
        port = request.POST.get('port')
        server_type = request.POST.get('server_type')
        php_version = request.POST.get('php_version')
        
        # 创建网站目录
        path = f'/www/wwwroot/{domain}'
        os.makedirs(path, exist_ok=True)
        
        # 创建网站记录
        website = Website.objects.create(
            name=name,
            domain=domain,
            path=path,
            port=port,
            server_type=server_type,
            php_version=php_version
        )
        
        # 生成服务器配置文件
        if server_type == 'nginx':
            generate_nginx_config(website)
        else:
            generate_apache_config(website)
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'创建网站 {domain}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, '网站创建成功')
        return redirect('website_detail', pk=website.pk)
    
    return render(request, 'websites/create.html')

@login_required
def website_detail(request, pk):
    website = get_object_or_404(Website, pk=pk)
    ssl_certs = website.sslcertificate_set.all().order_by('-created_at')
    backups = website.websitebackup_set.all().order_by('-created_at')
    
    context = {
        'website': website,
        'ssl_certs': ssl_certs,
        'backups': backups,
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
def website_delete(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    # 删除网站文件
    if os.path.exists(website.path):
        shutil.rmtree(website.path)
    
    # 删除配置文件
    config_path = f'/etc/nginx/sites-enabled/{website.domain}.conf' if website.server_type == 'nginx' else f'/etc/apache2/sites-enabled/{website.domain}.conf'
    if os.path.exists(config_path):
        os.remove(config_path)
    
    # 记录操作日志
    AuditLog.objects.create(
        user=request.user,
        action=f'删除网站 {website.domain}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    website.delete()
    messages.success(request, '网站已删除')
    return JsonResponse({'status': 'success'})

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
    """生成Nginx配置文件"""
    config = f"""server {{
    listen {website.port};
    server_name {website.domain};
    root {website.path};
    index index.html index.htm index.php;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    
    location ~ \.php$ {{
        fastcgi_pass unix:/run/php/php{website.php_version}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}"""
    
    config_path = f'/etc/nginx/sites-enabled/{website.domain}.conf'
    with open(config_path, 'w') as f:
        f.write(config)
    
    os.system('systemctl reload nginx')

def generate_apache_config(website):
    """生成Apache配置文件"""
    config = f"""<VirtualHost *:{website.port}>
    ServerName {website.domain}
    DocumentRoot {website.path}
    
    <Directory {website.path}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${{APACHE_LOG_DIR}}/{website.domain}.error.log
    CustomLog ${{APACHE_LOG_DIR}}/{website.domain}.access.log combined
</VirtualHost>"""
    
    config_path = f'/etc/apache2/sites-enabled/{website.domain}.conf'
    with open(config_path, 'w') as f:
        f.write(config)
    
    os.system('systemctl reload apache2')

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
