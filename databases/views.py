from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from .models import Database, DatabaseUser, DatabaseBackup, DatabaseBackupSchedule, DatabaseBackupExecution, DatabaseBackupSettings
from panel.models import AuditLog
import os
import subprocess
import shutil
from datetime import datetime
from django.db.models import Count, Avg
from django.utils import timezone
from django.conf import settings

@login_required
def database_list(request):
    databases = Database.objects.all().order_by('-created_at')
    return render(request, 'databases/list.html', {'databases': databases})

@login_required
def database_create(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        db_type = request.POST.get('db_type')
        username = request.POST.get('username')
        password = request.POST.get('password')
        port = request.POST.get('port')
        
        # 创建数据库
        if db_type == 'mysql':
            create_mysql_database(name, username, password)
            port = 3306
        elif db_type == 'postgresql':
            create_postgresql_database(name, username, password)
            port = 5432
        else:  # SQLite
            create_sqlite_database(name)
            port = 0
        
        # 创建数据库记录
        database = Database.objects.create(
            name=name,
            db_type=db_type,
            username=username,
            password=password,
            port=port
        )
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'创建{database.get_db_type_display()}数据库 {name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, '数据库创建成功')
        return redirect('database_detail', pk=database.pk)
    
    return render(request, 'databases/create.html')

@login_required
def database_detail(request, pk):
    database = get_object_or_404(Database, pk=pk)
    users = database.databaseuser_set.all()
    backups = database.databasebackup_set.all().order_by('-created_at')
    
    context = {
        'database': database,
        'users': users,
        'backups': backups,
    }
    return render(request, 'databases/detail.html', context)

@login_required
def database_backup(request, pk):
    database = get_object_or_404(Database, pk=pk)
    
    try:
        # 创建备份
        if database.db_type == 'mysql':
            backup_file = backup_mysql_database(database)
        elif database.db_type == 'postgresql':
            backup_file = backup_postgresql_database(database)
        else:
            backup_file = backup_sqlite_database(database)
        
        # 获取备份文件大小
        size = os.path.getsize(backup_file)
        
        # 创建备份记录
        backup = DatabaseBackup.objects.create(
            database=database,
            backup_file=backup_file,
            size=size
        )
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'备份数据库 {database.name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse({
            'success': True,
            'backup_id': backup.id,
            'backup_url': backup.backup_file.url
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def database_restore(request, pk):
    database = get_object_or_404(Database, pk=pk)
    backup_id = request.POST.get('backup_id')
    backup = get_object_or_404(DatabaseBackup, pk=backup_id, database=database)
    
    try:
        # 恢复备份
        if database.db_type == 'mysql':
            restore_mysql_database(database, backup.backup_file.path)
        elif database.db_type == 'postgresql':
            restore_postgresql_database(database, backup.backup_file.path)
        else:
            restore_sqlite_database(database, backup.backup_file.path)
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'恢复数据库 {database.name} 的备份',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, '数据库恢复成功')
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def database_delete(request, pk):
    database = get_object_or_404(Database, pk=pk)
    
    try:
        # 删除数据库
        if database.db_type == 'mysql':
            delete_mysql_database(database)
        elif database.db_type == 'postgresql':
            delete_postgresql_database(database)
        else:
            delete_sqlite_database(database)
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'删除数据库 {database.name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        database.delete()
        messages.success(request, '数据库已删除')
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def database_users(request, pk):
    database = get_object_or_404(Database, pk=pk)
    users = database.databaseuser_set.all()
    return render(request, 'databases/users.html', {
        'database': database,
        'users': users
    })

@login_required
def database_user_add(request, pk):
    database = get_object_or_404(Database, pk=pk)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        host = request.POST.get('host', '%')
        privileges = request.POST.get('privileges', 'ALL PRIVILEGES')
        
        try:
            # 创建数据库用户
            if database.db_type == 'mysql':
                create_mysql_user(database, username, password, host, privileges)
            elif database.db_type == 'postgresql':
                create_postgresql_user(database, username, password, privileges)
            
            # 创建用户记录
            DatabaseUser.objects.create(
                database=database,
                username=username,
                password=password,
                host=host,
                privileges=privileges
            )
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'为数据库 {database.name} 创建用户 {username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '数据库用户创建成功')
            return redirect('database_users', pk=database.pk)
        except Exception as e:
            messages.error(request, f'创建用户失败：{str(e)}')
    
    return render(request, 'databases/user_add.html', {'database': database})

@login_required
def database_user_delete(request, pk, user_pk):
    database = get_object_or_404(Database, pk=pk)
    db_user = get_object_or_404(DatabaseUser, pk=user_pk, database=database)
    
    try:
        # 删除数据库用户
        if database.db_type == 'mysql':
            delete_mysql_user(database, db_user.username, db_user.host)
        elif database.db_type == 'postgresql':
            delete_postgresql_user(database, db_user.username)
        
        # 记录操作日志
        AuditLog.objects.create(
            user=request.user,
            action=f'删除数据库 {database.name} 的用户 {db_user.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        db_user.delete()
        messages.success(request, '数据库用户已删除')
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

# 数据库操作辅助函数
def create_mysql_database(name, username, password):
    """创建MySQL数据库和用户"""
    commands = [
        f'mysql -e "CREATE DATABASE {name};"',
        f'mysql -e "CREATE USER \'{username}\'@\'%\' IDENTIFIED BY \'{password}\';"',
        f'mysql -e "GRANT ALL PRIVILEGES ON {name}.* TO \'{username}\'@\'%\';"',
        'mysql -e "FLUSH PRIVILEGES;"'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def create_postgresql_database(name, username, password):
    """创建PostgreSQL数据库和用户"""
    commands = [
        f'createuser -s {username}',
        f'psql -c "ALTER USER {username} WITH PASSWORD \'{password}\';"',
        f'createdb -O {username} {name}'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def create_sqlite_database(name):
    """创建SQLite数据库"""
    db_path = f'/www/database/sqlite/{name}.db'
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    open(db_path, 'a').close()
    os.chmod(db_path, 0o666)

def backup_mysql_database(database):
    """备份MySQL数据库"""
    backup_dir = f'/www/backup/mysql/{database.name}'
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = f'{backup_dir}/{database.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sql'
    
    cmd = f'mysqldump {database.name} > {backup_file}'
    subprocess.run(cmd, shell=True, check=True)
    
    return backup_file

def backup_postgresql_database(database):
    """备份PostgreSQL数据库"""
    backup_dir = f'/www/backup/postgresql/{database.name}'
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = f'{backup_dir}/{database.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sql'
    
    cmd = f'pg_dump {database.name} > {backup_file}'
    subprocess.run(cmd, shell=True, check=True)
    
    return backup_file

def backup_sqlite_database(database):
    """备份SQLite数据库"""
    backup_dir = f'/www/backup/sqlite/{database.name}'
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = f'{backup_dir}/{database.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    
    shutil.copy(f'/www/database/sqlite/{database.name}.db', backup_file)
    
    return backup_file

def restore_mysql_database(database, backup_file):
    """恢复MySQL数据库"""
    cmd = f'mysql {database.name} < {backup_file}'
    subprocess.run(cmd, shell=True, check=True)

def restore_postgresql_database(database, backup_file):
    """恢复PostgreSQL数据库"""
    cmd = f'psql {database.name} < {backup_file}'
    subprocess.run(cmd, shell=True, check=True)

def restore_sqlite_database(database, backup_file):
    """恢复SQLite数据库"""
    db_path = f'/www/database/sqlite/{database.name}.db'
    shutil.copy(backup_file, db_path)
    os.chmod(db_path, 0o666)

def delete_mysql_database(database):
    """删除MySQL数据库"""
    commands = [
        f'mysql -e "DROP DATABASE {database.name};"',
        f'mysql -e "DROP USER \'{database.username}\'@\'%\';"'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def delete_postgresql_database(database):
    """删除PostgreSQL数据库"""
    commands = [
        f'dropdb {database.name}',
        f'dropuser {database.username}'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def delete_sqlite_database(database):
    """删除SQLite数据库"""
    db_path = f'/www/database/sqlite/{database.name}.db'
    if os.path.exists(db_path):
        os.remove(db_path)

def create_mysql_user(database, username, password, host, privileges):
    """创建MySQL用户"""
    commands = [
        f'mysql -e "CREATE USER \'{username}\'@\'{host}\' IDENTIFIED BY \'{password}\';"',
        f'mysql -e "GRANT {privileges} ON {database.name}.* TO \'{username}\'@\'{host}\';"',
        'mysql -e "FLUSH PRIVILEGES;"'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def create_postgresql_user(database, username, password, privileges):
    """创建PostgreSQL用户"""
    commands = [
        f'createuser {username}',
        f'psql -c "ALTER USER {username} WITH PASSWORD \'{password}\';"',
        f'psql -c "GRANT {privileges} ON DATABASE {database.name} TO {username};"'
    ]
    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

def delete_mysql_user(database, username, host):
    """删除MySQL用户"""
    cmd = f'mysql -e "DROP USER \'{username}\'@\'{host}\';"'
    subprocess.run(cmd, shell=True, check=True)

def delete_postgresql_user(database, username):
    """删除PostgreSQL用户"""
    cmd = f'dropuser {username}'
    subprocess.run(cmd, shell=True, check=True)

@login_required
def database_backup_schedule(request, pk):
    database = get_object_or_404(Database, pk=pk)
    schedules = DatabaseBackupSchedule.objects.filter(database=database)
    execution_records = DatabaseBackupExecution.objects.filter(schedule__database=database)
    
    # 计算统计数据
    total_executions = execution_records.count()
    success_count = execution_records.filter(status='success').count()
    success_rate = round(success_count / total_executions * 100) if total_executions > 0 else 0
    
    # 计算总备份大小
    total_backup_size = sum(record.backup_file.size for record in execution_records if record.backup_file)
    
    # 获取最后一次备份时间
    last_backup = execution_records.filter(status='success').first()
    last_backup_time = last_backup.completed_at if last_backup else None
    
    # 获取备份设置
    settings, created = DatabaseBackupSettings.objects.get_or_create(database=database)
    
    context = {
        'database': database,
        'schedules': schedules,
        'execution_records': execution_records[:50],  # 只显示最近50条记录
        'success_rate': success_rate,
        'total_backup_size': total_backup_size,
        'last_backup_time': last_backup_time,
        'settings': settings,
    }
    
    return render(request, 'databases/backup_schedule.html', context)

@login_required
def save_backup_schedule(request, pk):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})
    
    database = get_object_or_404(Database, pk=pk)
    schedule_id = request.POST.get('schedule_id')
    
    if schedule_id:
        schedule = get_object_or_404(DatabaseBackupSchedule, pk=schedule_id, database=database)
    else:
        schedule = DatabaseBackupSchedule(database=database)
    
    # 更新计划信息
    schedule.name = request.POST.get('name')
    schedule.schedule_type = request.POST.get('schedule_type')
    schedule.time = request.POST.get('time')
    schedule.backup_type = request.POST.get('backup_type')
    schedule.keep_backups = request.POST.get('keep_backups')
    
    # 根据计划类型设置额外字段
    if schedule.schedule_type == 'weekly':
        schedule.weekday = request.POST.get('weekday')
        schedule.day = None
    elif schedule.schedule_type == 'monthly':
        schedule.weekday = None
        schedule.day = request.POST.get('day')
    else:
        schedule.weekday = None
        schedule.day = None
    
    schedule.save()
    return JsonResponse({'status': 'success'})

@login_required
def get_backup_schedule(request, pk, schedule_id):
    database = get_object_or_404(Database, pk=pk)
    schedule = get_object_or_404(DatabaseBackupSchedule, pk=schedule_id, database=database)
    
    data = {
        'name': schedule.name,
        'schedule_type': schedule.schedule_type,
        'weekday': schedule.weekday,
        'day': schedule.day,
        'time': schedule.time.strftime('%H:%M'),
        'backup_type': schedule.backup_type,
        'keep_backups': schedule.keep_backups,
    }
    
    return JsonResponse(data)

@login_required
def toggle_backup_schedule(request, pk, schedule_id):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})
    
    database = get_object_or_404(Database, pk=pk)
    schedule = get_object_or_404(DatabaseBackupSchedule, pk=schedule_id, database=database)
    
    schedule.is_active = not schedule.is_active
    schedule.save()
    
    return JsonResponse({'status': 'success'})

@login_required
def delete_backup_schedule(request, pk, schedule_id):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': '不支持的请求方法'})
    
    database = get_object_or_404(Database, pk=pk)
    schedule = get_object_or_404(DatabaseBackupSchedule, pk=schedule_id, database=database)
    
    schedule.delete()
    return JsonResponse({'status': 'success'})

@login_required
def database_backup_settings(request, pk):
    database = get_object_or_404(Database, pk=pk)
    settings, created = DatabaseBackupSettings.objects.get_or_create(database=database)
    
    if request.method == 'POST':
        # 更新基本设置
        settings.storage_type = request.POST.get('storage_type')
        settings.compression = request.POST.get('compression')
        settings.encrypt_backup = request.POST.get('encrypt_backup') == 'on'
        
        # 根据存储类型更新相关设置
        if settings.storage_type == 'ftp':
            settings.ftp_host = request.POST.get('ftp_host')
            settings.ftp_username = request.POST.get('ftp_username')
            if request.POST.get('ftp_password'):  # 只在提供新密码时更新
                settings.ftp_password = request.POST.get('ftp_password')
        elif settings.storage_type == 's3':
            settings.s3_access_key = request.POST.get('s3_access_key')
            if request.POST.get('s3_secret_key'):  # 只在提供新密钥时更新
                settings.s3_secret_key = request.POST.get('s3_secret_key')
            settings.s3_bucket = request.POST.get('s3_bucket')
        
        settings.save()
        return redirect('database_backup_schedule', pk=pk)
    
    return redirect('database_backup_schedule', pk=pk)

@login_required
def database_export(request, pk):
    database = get_object_or_404(Database, pk=pk)
    
    if request.method == 'POST':
        try:
            # 获取导出选项
            export_structure = request.POST.get('export_structure', 'on') == 'on'
            export_data = request.POST.get('export_data', 'on') == 'on'
            compression = request.POST.get('compression', 'none')
            
            # 获取备份设置
            backup_settings = DatabaseBackupSettings.objects.filter(database=database).first()
            
            # 创建备份处理器
            handler = DatabaseBackupHandler(database, backup_settings)
            
            # 导出数据库
            backup_file = handler.export_database(
                include_schema=export_structure,
                include_data=export_data
            )
            
            # 处理备份文件（压缩等）
            if compression != 'none':
                backup_settings = type('Settings', (), {'compression': compression})()
                handler.backup_settings = backup_settings
                backup_file = handler.process_backup_file(backup_file)
            
            # 存储备份文件
            stored_path = handler.store_backup_file(backup_file)
            
            # 创建备份记录
            backup = DatabaseBackup.objects.create(
                database=database,
                backup_file=stored_path,
                size=os.path.getsize(backup_file),
                note=f"手动导出 - {'包含表结构' if export_structure else ''} {'包含数据' if export_data else ''}"
            )
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'导出数据库 {database.name}',
                ip_address=request.META.get('REMOTE_ADDR'),
                details=f"导出选项: 结构={export_structure}, 数据={export_data}, 压缩={compression}"
            )
            
            messages.success(request, '数据库导出成功')
            return redirect('database_detail', pk=pk)
            
        except Exception as e:
            messages.error(request, f'导出失败：{str(e)}')
            return redirect('database_detail', pk=pk)
    
    return render(request, 'databases/import_export.html', {
        'database': database,
        'import_history': [],  # TODO: 实现导入历史记录
        'export_history': DatabaseBackup.objects.filter(database=database).order_by('-created_at')[:10]
    })

@login_required
def delete_export(request, pk, export_id):
    if request.method == 'POST':
        database = get_object_or_404(Database, pk=pk)
        backup = get_object_or_404(DatabaseBackup, pk=export_id, database=database)
        
        try:
            # 删除备份文件
            if backup.backup_file:
                file_path = os.path.join(settings.MEDIA_ROOT, str(backup.backup_file))
                if os.path.exists(file_path):
                    os.remove(file_path)
            
            # 删除记录
            backup.delete()
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'删除数据库导出 {database.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '导出记录已删除')
        except Exception as e:
            messages.error(request, f'删除失败：{str(e)}')
        
        return redirect('database_detail', pk=pk)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)

@login_required
def database_import(request, pk):
    database = get_object_or_404(Database, pk=pk)
    
    if request.method == 'POST':
        try:
            # 获取导入选项
            import_file = request.FILES.get('import_file')
            clear_database = request.POST.get('clear_database') == 'on'
            
            if not import_file:
                messages.error(request, '请选择要导入的文件')
                return redirect('database_detail', pk=pk)
            
            # 验证文件类型
            allowed_extensions = ['.sql', '.gz', '.zip']
            if not any(import_file.name.endswith(ext) for ext in allowed_extensions):
                messages.error(request, '不支持的文件类型，请上传 .sql、.sql.gz 或 .sql.zip 文件')
                return redirect('database_detail', pk=pk)
            
            # 获取备份设置
            backup_settings = DatabaseBackupSettings.objects.filter(database=database).first()
            
            # 创建备份处理器
            handler = DatabaseBackupHandler(database, backup_settings)
            
            # 导入数据库
            handler.import_database(import_file, clear_database)
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'导入数据库 {database.name}',
                ip_address=request.META.get('REMOTE_ADDR'),
                details=f"文件名: {import_file.name}, 清空数据库: {clear_database}"
            )
            
            messages.success(request, '数据库导入成功')
            return redirect('database_detail', pk=pk)
            
        except Exception as e:
            messages.error(request, f'导入失败：{str(e)}')
            return redirect('database_detail', pk=pk)
    
    return render(request, 'databases/import_export.html', {
        'database': database,
        'import_history': [],  # TODO: 实现导入历史记录
        'export_history': DatabaseBackup.objects.filter(database=database).order_by('-created_at')[:10]
    })

@login_required
def delete_import(request, pk, import_id):
    if request.method == 'POST':
        database = get_object_or_404(Database, pk=pk)
        import_record = get_object_or_404(DatabaseImport, pk=import_id, database=database)
        
        try:
            # 删除导入记录
            import_record.delete()
            
            # 记录操作日志
            AuditLog.objects.create(
                user=request.user,
                action=f'删除数据库导入记录 {database.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, '导入记录已删除')
        except Exception as e:
            messages.error(request, f'删除失败：{str(e)}')
        
        return redirect('database_detail', pk=pk)
    
    return JsonResponse({'status': 'error', 'message': '方法不允许'}, status=405)
