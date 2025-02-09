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

def setup_php_fpm(version, domain):
    """设置 PHP-FPM 配置"""
    version_num = version.replace('.', '')
    port = f'90{version_num}'  # 例如：9074, 9080
    
    # 修改 PHP-FPM 配置文件路径
    fpm_config_dir = f'/etc/php/php-fpm.d'
    fpm_config_file = os.path.join(fpm_config_dir, 'www.conf')
    
    if os.path.exists(fpm_config_file):
        backup_file = f'{fpm_config_file}.backup'
        if not os.path.exists(backup_file):
            shutil.copy2(fpm_config_file, backup_file)
    
    # 修改 PHP-FPM 配置，使用 TCP 端口监听
    fpm_config = f"""[www]
user = www
group = www
listen = 127.0.0.1:{port}
listen.owner = www
listen.group = www
listen.mode = 0660
listen.allowed_clients = 127.0.0.1

pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 1000

php_admin_value[error_log] = /www/wwwlogs/php{version_num}_error.log
php_admin_flag[log_errors] = on
php_admin_value[upload_max_filesize] = 32M

; 添加打开目录的权限
security.limit_extensions = .php .php3 .php4 .php5 .php7 .php8
php_admin_value[open_basedir] = /www/wwwroot/{domain}/:/tmp/:/proc/
"""
    
    os.makedirs(fpm_config_dir, exist_ok=True)
    
    with open(fpm_config_file, 'w') as f:
        f.write(fpm_config)
    
    # 确保 PHP-FPM 目录权限正确
    os.system(f'chown -R www:www {fpm_config_dir}')
    os.system(f'chmod -R 755 {fpm_config_dir}')
    
    # 重启 PHP-FPM 服务
    os.system(f'systemctl restart php{version_num}-fpm')
    
    return port

@login_required
def website_list(request):
    websites = Website.objects.all()
    return render(request, 'websites/list.html', {'websites': websites})

@login_required
def website_create(request):
    if request.method == 'POST':
        form = WebsiteForm(request.POST)
        if form.is_valid():
            try:
                # 先创建网站对象
                website = form.save(commit=False)
                website.user = request.user
                website.php_version = form.cleaned_data['php_version']
                website.save()
                
                # 创建网站目录并设置正确的权限
                path = os.path.join('/www/wwwroot', website.domain)
                os.makedirs(path, exist_ok=True)
                
                # 创建网站默认首页
                index_content = """<!DOCTYPE html>
<html>
<head>
    <title>Welcome to {}</title>
</head>
<body>
    <h1>Welcome to {}</h1>
    <p>Site is working!</p>
</body>
</html>""".format(website.domain, website.domain)
                
                with open(os.path.join(path, 'index.php'), 'w') as f:
                    f.write(index_content)
                
                # 设置目录权限
                os.system(f'chown -R www:www {path}')
                os.system(f'chmod -R 755 {path}')
                os.system(f'find {path} -type d -exec chmod 755 {{}} \\;')
                os.system(f'find {path} -type f -exec chmod 644 {{}} \\;')
                
                # 传入 domain 参数
                php_port = setup_php_fpm(website.php_version, website.domain)
                
                nginx_config = f"""server {{
    listen {website.port};
    server_name {website.domain};
    root /www/wwwroot/{website.domain};
    index index.php index.html index.htm;

    access_log  /www/wwwlogs/{website.domain}.log;
    error_log  /www/wwwlogs/{website.domain}.error.log;

    # PHP 配置
    location ~ [^/]\.php(/|$) {{
        try_files $uri =404;
        fastcgi_pass   127.0.0.1:{php_port};
        fastcgi_index  index.php;
        include        fastcgi.conf;
        include        fastcgi_params;
        fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        fastcgi_param  PHP_ADMIN_VALUE  "open_basedir=/www/wwwroot/{website.domain}/:/tmp/:/proc/";
    }}

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
        if (!-e $request_filename) {{
            rewrite ^(.*)$ /index.php?s=$1 last;
            break;
        }}
    }}

    # 允许访问目录
    location ~ ^/(\.user.ini|\.htaccess|\.git|\.env|\.svn|\.project|LICENSE|README.md) {{
        deny all;
    }}

    # 静态文件缓存
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|ico)$ {{
        expires      30d;
        access_log off;
    }}

    location ~ .*\.(js|css)?$ {{
        expires      12h;
        access_log off;
    }}
}}"""
                
                nginx_path = f'/etc/nginx/conf.d/{website.domain}.conf'
                os.makedirs(os.path.dirname(nginx_path), exist_ok=True)
                
                with open(nginx_path, 'w') as f:
                    f.write(nginx_config)
                
                # 创建并设置日志目录权限
                os.makedirs('/www/wwwlogs', exist_ok=True)
                os.system('chown -R www:www /www/wwwlogs')
                os.system('chmod -R 755 /www/wwwlogs')
                
                # 测试并重启 Nginx
                if os.system('nginx -t') == 0:
                    os.system('systemctl reload nginx')
                else:
                    messages.warning(request, 'Nginx 配置测试失败，请检查配置文件')

                Website.objects.filter(id=website.id).update(
                    path=path,
                    nginx_config_path=nginx_path
                )
                
                messages.success(request, '网站创建成功！')
                return redirect('website_list')
                
            except Exception as e:
                if website.id:
                    website.delete()
                messages.error(request, f'创建网站失败: {str(e)}')
                return redirect('website_list')
    else:
        form = WebsiteForm()

    # 获取已安装的 PHP 版本
    installed_php_versions = ApplicationInstallation.objects.filter(
        application__name__icontains='php',  # 使用 icontains 替代 ilike
        status='success'
    ).select_related('application').values_list(
        'application__version', 
        flat=True
    ).distinct()
    
    # 转换查询结果为列表并排序
    installed_php_versions = list(installed_php_versions)
    
    # 如果数据库中没有找到已安装的版本，提供默认版本列表
    if not installed_php_versions:
        # 先尝试直接从 Application 表获取 PHP 版本
        php_versions = Application.objects.filter(
            name__icontains='php'  # 使用 icontains 替代 ilike
        ).values_list('version', flat=True).distinct()
        
        installed_php_versions = list(php_versions) or ['7.4', '8.0', '8.1', '8.2']
    
    # 版本号排序
    try:
        installed_php_versions = sorted(
            installed_php_versions,
            key=lambda x: [int(i) for i in x.split('.')]
        )
    except (ValueError, AttributeError):
        # 如果排序出错，至少确保有序显示
        installed_php_versions = sorted(installed_php_versions)

    context = {
        'form': form,
        'installed_php_versions': installed_php_versions
    }
    return render(request, 'websites/form.html', context)

@login_required
def website_edit(request, pk):
    website = get_object_or_404(Website, pk=pk)
    
    # 从 ApplicationInstallation 获取已安装的 PHP 版本
    installed_php_versions = ApplicationInstallation.objects.filter(
        application__name__startswith='PHP',
        status='installed'
    ).values_list('application__version', flat=True)
    
    # 排序版本号
    installed_php_versions = sorted(installed_php_versions)
    
    if request.method == 'POST':
        form = WebsiteForm(request.POST, instance=website)
        if form.is_valid():
            website = form.save()
            
            # 删除所有现有的附加域名
            website.additional_domains.all().delete()
            
            # 添加新的附加域名
            additional_domains = request.POST.getlist('additional_domains[]')
            for domain in additional_domains:
                if domain.strip():  # 只处理非空域名
                    AdditionalDomain.objects.create(
                        website=website,
                        domain=domain.strip()
                    )
            
            # 如果路径改变，移动网站目录
            old_path = website.path
            if old_path != website.path:
                try:
                    shutil.move(old_path, website.path)
                except Exception as e:
                    messages.error(request, f'移动网站目录失败: {str(e)}')
                    return render(request, 'websites/form.html', {'form': form})
            
            # 记录审计日志
            AuditLog.objects.create(
                user=request.user,
                action=f'编辑网站: {website.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '网站更新成功')
            return redirect('website_list')
    else:
        form = WebsiteForm(instance=website)
    
    context = {
        'form': form,
        'installed_php_versions': installed_php_versions,
        'website': website,  # 添加这行
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
