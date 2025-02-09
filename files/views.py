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
from datetime import timezone, timedelta, datetime
from django.urls import reverse
import requests
from urllib.parse import urlparse
import json
import zipfile
import tarfile

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
    
    # 防止访问特殊目录
    sensitive_dirs = {'/proc', '/sys', '/run', '/boot', '/etc/shadow', '/etc/passwd', '/dev'}
    if any(current_path.startswith(sensitive_dir) for sensitive_dir in sensitive_dirs):
        messages.error(request, '访问被拒绝：系统敏感目录')
        return redirect('file_browse')
    
    try:
        # 直接使用 Path 对象处理路径，避免符号链接循环
        path_obj = Path(current_path).resolve(strict=False)
        full_path = str(path_obj)
        
        # 检查解析后的路径是否在敏感目录中
        if any(full_path.startswith(sensitive_dir) for sensitive_dir in sensitive_dirs):
            messages.error(request, '访问被拒绝：系统敏感目录')
            return redirect('file_browse')
            
    except RuntimeError as e:
        messages.error(request, '符号链接解析错误')
        return redirect('file_browse')
    except Exception as e:
        messages.error(request, f'路径错误：{str(e)}')
        return redirect('file_browse')
    
    # 如果路径不存在，创建目录
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    
    # 获取目录内容
    items = []
    try:
        for item in os.scandir(full_path):
            stats = item.stat()
            size_kb = stats.st_size / 1024 if not item.is_dir() else get_dir_size(item.path) / 1024
            
            # 转换时间戳为本地时间
            modified_time = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            items.append({
                'name': item.name,
                'path': os.path.join(current_path, item.name),
                'is_dir': item.is_dir(),
                'size': round(size_kb, 2),  # 保留两位小数
                'size_unit': 'KB',
                'modified_time': modified_time,
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
    try:
        for entry in os.scandir(path):
            try:
                # 使用 Path 对象安全地处理符号链接
                path_obj = Path(entry.path).resolve(strict=False)
                
                # 如果是符号链接，跳过
                if os.path.islink(entry.path):
                    continue
                    
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += get_dir_size(entry.path)
            except (OSError, RuntimeError):
                # 忽略符号链接错误和其他文件访问错误
                continue
    except (OSError, PermissionError):
        # 如果目录不可访问，返回0
        return 0
        
    return total

@login_required
def paste_files(request):
    data = json.loads(request.body)
    files = data['files']
    action = data['action']
    destination = data['destination']
    
    try:
        for file_path in files:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(destination, filename)
            
            if action == 'cut':
                shutil.move(file_path, dest_path)
            else:  # copy
                if os.path.isdir(file_path):
                    shutil.copytree(file_path, dest_path)
                else:
                    shutil.copy2(file_path, dest_path)
                    
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@login_required
def batch_delete(request):
    data = json.loads(request.body)
    files = data['files']
    
    try:
        for file_path in files:
            if os.path.isdir(file_path):
                shutil.rmtree(file_path)
            else:
                os.remove(file_path)
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@login_required
def compress_files(request):
    data = json.loads(request.body)
    files = data['files']
    archive_name = data['name']
    format = data['format']
    current_path = data['path']
    
    try:
        if format == 'zip':
            archive_path = os.path.join(current_path, f'{archive_name}.zip')
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in files:
                    if os.path.isdir(file_path):
                        for root, _, filenames in os.walk(file_path):
                            for filename in filenames:
                                file_full_path = os.path.join(root, filename)
                                arcname = os.path.relpath(file_full_path, os.path.dirname(file_path))
                                zf.write(file_full_path, arcname)
                    else:
                        zf.write(file_path, os.path.basename(file_path))
        
        elif format in ['tar', 'gzip']:
            archive_path = os.path.join(current_path, f'{archive_name}.tar.gz')
            with tarfile.open(archive_path, 'w:gz') as tar:
                for file_path in files:
                    tar.add(file_path, arcname=os.path.basename(file_path))
                    
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@login_required
def remote_download(request):
    data = json.loads(request.body)
    url = data['url']
    filename = data['filename']
    current_path = data['path']
    
    try:
        if not filename:
            filename = os.path.basename(urlparse(url).path)
            if not filename:
                filename = 'downloaded_file'
                
        file_path = os.path.join(current_path, filename)
        
        # 下载文件
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@login_required
def file_edit(request):
    """编辑文件"""
    file_path = request.GET.get('path', '')
    
    # 检查文件是否存在
    if not os.path.isfile(file_path):
        messages.error(request, '文件不存在')
        return redirect('file_browse')
    
    try:
        # 尝试以文本方式读取文件
        encodings = ['utf-8', 'gbk', 'iso-8859-1', 'ascii']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
                
        if content is None:
            # 如果所有编码都失败，可能是二进制文件
            messages.warning(request, '此文件可能是二进制文件，编辑时请小心')
            # 尝试以二进制方式读取，并转换为十六进制显示
            with open(file_path, 'rb') as f:
                binary_content = f.read()
                content = binary_content.hex()
        
        return_path = os.path.dirname(file_path)
        
        context = {
            'file_path': file_path,
            'content': content,
            'return_path': return_path,
            'is_binary': content and all(ord(c) < 32 and c != '\n' and c != '\r' and c != '\t' for c in content[:1024])
        }
        return render(request, 'files/editor.html', context)
        
    except Exception as e:
        messages.error(request, f'读取文件失败：{str(e)}')
        return redirect('file_browse')

@login_required
def file_edit_save(request):
    """保存编辑后的文件内容"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '不支持的请求方法'}, status=405)
    
    try:
        data = json.loads(request.body)
        file_path = data.get('path')
        content = data.get('content')
        
        if not file_path or content is None:
            return JsonResponse({'status': 'error', 'message': '参数错误'}, status=400)
        
        # 检查文件是否存在
        if not os.path.isfile(file_path):
            return JsonResponse({'status': 'error', 'message': '文件不存在'}, status=404)
        
        # 尝试以文本方式保存
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except UnicodeEncodeError:
            # 如果是二进制内容（十六进制格式），转换回二进制保存
            try:
                binary_content = bytes.fromhex(content)
                with open(file_path, 'wb') as f:
                    f.write(binary_content)
            except ValueError:
                return JsonResponse({'status': 'error', 'message': '无效的二进制内容'}, status=400)
            
        return JsonResponse({'status': 'success'})
        
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
