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
                website.save()
                
                # 创建网站目录
                path = os.path.join('/www/wwwroot', website.domain)
                os.makedirs(path, exist_ok=True)
                
                # 更新网站路径并保存
                Website.objects.filter(id=website.id).update(path=path)
                
                messages.success(request, '网站创建成功！')
                return redirect('website_list')
            except Exception as e:
                if website.id:
                    website.delete()
                messages.error(request, f'创建网站目录失败: {str(e)}')
                return redirect('website_list')
    else:
        form = WebsiteForm()

    # 获取已安装的 PHP 版本
    def get_installed_php_versions():
        try:
            # 获取 /www/server/php/ 目录下的所有文件夹
            php_path = '/www/server/php'
            if os.path.exists(php_path):
                versions = [d for d in os.listdir(php_path) if os.path.isdir(os.path.join(php_path, d))]
                return sorted(versions)
        except Exception:
            pass
        return []

    context = {
        'form': form,
        'installed_php_versions': get_installed_php_versions()
    }
    return render(request, 'websites/form.html', context)

@login_required
def website_edit(request, pk):
    website = get_object_or_404(Website, pk=pk)
    installed_php_versions = get_installed_php_versions()
    print(f"检测到的PHP版本: {installed_php_versions}")  # 添加调试信息
    
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

def generate_nginx_config(website):
    """生成Nginx配置文件"""
    config_dir = '/etc/nginx/conf.d'
    config_file = f'{config_dir}/{website.domain}.conf'
    
    # 准备域名列表
    all_domains = [website.domain] + [domain.domain for domain in website.additional_domains.all()]
    server_name = ' '.join(all_domains)
    
    # 网站根目录
    root_path = os.path.join('/www/wwwroot', website.domain)
    os.makedirs(root_path, exist_ok=True)
    
    config = f"""server {{
    listen {website.port};
    server_name {server_name};
    root {root_path};
    index index.html index.htm index.php;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    
    # 错误页面
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {{
        root /www/wwwroot;
    }}
    """
    
    # 如果启用了PHP
    if website.php_version:
        config += f"""
    # PHP配置
    location ~ \.php$ {{
        fastcgi_pass unix:/run/php/php{website.php_version}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
    """
    
    config += "}\n"
    
    # 写入配置文件
    with open(config_file, 'w') as f:
        f.write(config)
    
    # 测试配置文件
    os.system('nginx -t')
    
    # 重新加载Nginx
    os.system('systemctl reload nginx')

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

    # 从系统配置获取已安装的PHP版本
    php_versions = SystemConfig.objects.filter(
        name__startswith='php_',
        status='installed'
    ).values_list('name', flat=True)
    
    # 处理版本号格式
    php_versions = [version.replace('php_', '') for version in php_versions]
    
    context = {
        'form': form,
        'php_versions': php_versions,
        'website': website,
    }
    return render(request, 'websites/form.html', context)
