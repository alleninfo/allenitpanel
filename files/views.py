from django.shortcuts import render
import os
import shutil
import mimetypes
from pathlib import Path
from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib import messages
from django.utils.http import quote
from django.conf import settings
from .models import FileShare, FileOperation
import uuid
from datetime import timezone, timedelta
from django.urls import reverse

# Create your views here.

@login_required
def file_manager(request):
    """文件管理器主页"""
    return redirect('file_browse')

@login_required
def file_browse(request):
    """浏览文件和目录"""
    current_path = request.GET.get('path', '/')
    current_path = os.path.normpath(current_path)
    
    # 防止访问上级目录
    if '..' in current_path:
        messages.error(request, '非法的路径')
        return redirect('file_browse')
    
    # 获取完整路径
    full_path = os.path.join(settings.MEDIA_ROOT, current_path.lstrip('/'))
    
    # 如果路径不存在，创建目录
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    
    # 获取目录内容
    items = []
    try:
        for item in os.scandir(full_path):
            stats = item.stat()
            items.append({
                'name': item.name,
                'path': os.path.join(current_path, item.name),
                'is_dir': item.is_dir(),
                'size': stats.st_size if not item.is_dir() else get_dir_size(item.path),
                'modified_time': stats.st_mtime,
                'permissions': oct(stats.st_mode)[-3:]
            })
        
        # 按照类型和名称排序
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    except PermissionError:
        messages.error(request, '没有权限访问此目录')
        return redirect('file_browse')
    
    # 获取路径导航
    path_parts = []
    temp_path = ''
    for part in current_path.split('/'):
        if part:
            temp_path = os.path.join(temp_path, part)
            path_parts.append({
                'name': part,
                'path': temp_path
            })
    
    context = {
        'current_path': current_path,
        'parent_path': os.path.dirname(current_path),
        'path_parts': path_parts,
        'items': items
    }
    return render(request, 'files/manager.html', context)

@login_required
def file_upload(request):
    """上传文件"""
    if request.method == 'POST':
        path = request.POST.get('path', '/')
        files = request.FILES.getlist('file')
        
        # 获取目标目录的完整路径
        target_dir = os.path.join(settings.MEDIA_ROOT, path.lstrip('/'))
        
        try:
            for file in files:
                # 构建文件保存路径
                file_path = os.path.join(target_dir, file.name)
                
                # 保存文件
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                # 记录操作日志
                FileOperation.objects.create(
                    user=request.user,
                    operation_type='upload',
                    file_path=os.path.join(path, file.name),
                    size=file.size,
                    ip_address=request.META.get('REMOTE_ADDR')
                )
            
            messages.success(request, '文件上传成功')
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def file_download(request):
    """下载文件"""
    path = request.GET.get('path', '')
    if not path:
        messages.error(request, '未指定文件')
        return redirect('file_browse')
    
    # 获取文件的完整路径
    file_path = os.path.join(settings.MEDIA_ROOT, path.lstrip('/'))
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        messages.error(request, '文件不存在')
        return redirect('file_browse')
    
    try:
        # 记录操作日志
        FileOperation.objects.create(
            user=request.user,
            operation_type='download',
            file_path=path,
            size=os.path.getsize(file_path),
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        # 获取文件类型
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'
        
        # 返回文件
        response = FileResponse(open(file_path, 'rb'), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename*=UTF-8\'\'{quote(os.path.basename(file_path))}'
        return response
    except Exception as e:
        messages.error(request, f'下载失败：{str(e)}')
        return redirect('file_browse')

@login_required
def create_folder(request):
    """创建文件夹"""
    if request.method == 'POST':
        path = request.POST.get('path', '/')
        name = request.POST.get('name')
        
        if not name:
            return JsonResponse({'status': 'error', 'message': '文件夹名称不能为空'}, status=400)
        
        # 获取完整路径
        folder_path = os.path.join(settings.MEDIA_ROOT, path.lstrip('/'), name)
        
        try:
            os.makedirs(folder_path)
            
            # 记录操作日志
            FileOperation.objects.create(
                user=request.user,
                operation_type='create',
                file_path=os.path.join(path, name),
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '文件夹创建成功')
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def file_rename(request):
    """重命名文件或文件夹"""
    if request.method == 'POST':
        path = request.POST.get('path')
        new_name = request.POST.get('new_name')
        
        if not path or not new_name:
            return JsonResponse({'status': 'error', 'message': '参数错误'}, status=400)
        
        # 获取完整路径
        old_path = os.path.join(settings.MEDIA_ROOT, path.lstrip('/'))
        new_path = os.path.join(os.path.dirname(old_path), new_name)
        
        try:
            os.rename(old_path, new_path)
            
            # 记录操作日志
            FileOperation.objects.create(
                user=request.user,
                operation_type='rename',
                file_path=path,
                new_path=os.path.join(os.path.dirname(path), new_name),
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '重命名成功')
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def file_delete(request):
    """删除文件或文件夹"""
    if request.method == 'POST':
        path = request.POST.get('path')
        
        if not path:
            return JsonResponse({'status': 'error', 'message': '参数错误'}, status=400)
        
        # 获取完整路径
        full_path = os.path.join(settings.MEDIA_ROOT, path.lstrip('/'))
        
        try:
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
            else:
                os.remove(full_path)
            
            # 记录操作日志
            FileOperation.objects.create(
                user=request.user,
                operation_type='delete',
                file_path=path,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '删除成功')
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def file_share(request):
    """创建文件分享链接"""
    if request.method == 'POST':
        path = request.POST.get('path')
        expires_days = int(request.POST.get('expires_days', 7))
        
        if not path:
            return JsonResponse({'status': 'error', 'message': '参数错误'}, status=400)
        
        # 生成分享令牌
        share_token = str(uuid.uuid4())
        
        # 创建分享记录
        share = FileShare.objects.create(
            name=os.path.basename(path),
            file_path=path,
            share_token=share_token,
            created_by=request.user,
            expires_at=timezone.now() + timedelta(days=expires_days)
        )
        
        # 生成分享链接
        share_url = request.build_absolute_uri(
            reverse('file_share_download', args=[share_token])
        )
        
        return JsonResponse({
            'status': 'success',
            'share_url': share_url
        })
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

def file_share_download(request, token):
    """下载分享的文件"""
    share = get_object_or_404(FileShare, share_token=token)
    
    # 检查是否过期
    if share.expires_at and share.expires_at < timezone.now():
        messages.error(request, '分享链接已过期')
        return redirect('file_browse')
    
    # 获取文件完整路径
    file_path = os.path.join(settings.MEDIA_ROOT, share.file_path.lstrip('/'))
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        messages.error(request, '文件不存在')
        return redirect('file_browse')
    
    try:
        # 更新下载次数
        share.download_count += 1
        share.save()
        
        # 获取文件类型
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'
        
        # 返回文件
        response = FileResponse(open(file_path, 'rb'), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename*=UTF-8\'\'{quote(share.name)}'
        return response
    except Exception as e:
        messages.error(request, f'下载失败：{str(e)}')
        return redirect('file_browse')

def get_dir_size(path):
    """获取目录大小"""
    total = 0
    for entry in os.scandir(path):
        if entry.is_file():
            total += entry.stat().st_size
        elif entry.is_dir():
            total += get_dir_size(entry.path)
    return total
