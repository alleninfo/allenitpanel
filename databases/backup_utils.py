import os
import subprocess
import gzip
import zipfile
import shutil
import tempfile
from datetime import datetime
from django.conf import settings
from django.core.files import File
from ftplib import FTP
import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class DatabaseBackupHandler:
    def __init__(self, database, backup_settings=None):
        self.database = database
        self.backup_settings = backup_settings
        self.temp_dir = tempfile.mkdtemp()
    
    def __del__(self):
        # 清理临时目录
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def export_database(self, include_schema=True, include_data=True):
        """导出数据库"""
        try:
            if self.database.db_type == 'mysql':
                return self._export_mysql(include_schema, include_data)
            elif self.database.db_type == 'postgresql':
                return self._export_postgresql(include_schema, include_data)
            elif self.database.db_type == 'sqlite':
                return self._export_sqlite()
            else:
                raise ValueError(f"不支持的数据库类型: {self.database.db_type}")
        except Exception as e:
            logger.error(f"导出数据库失败: {str(e)}")
            raise
    
    def _export_mysql(self, include_schema, include_data):
        """导出MySQL数据库"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.temp_dir, f"{self.database.name}_{timestamp}.sql")
        
        # 构建mysqldump命令
        cmd = ['mysqldump']
        if not include_schema:
            cmd.append('--no-create-info')
        if not include_data:
            cmd.append('--no-data')
        
        # 添加其他选项
        cmd.extend([
            '--single-transaction',  # 保证数据一致性
            '--quick',              # 大表处理优化
            '--set-charset',        # 设置字符集
            f'--databases {self.database.name}'
        ])
        
        # 执行导出
        with open(output_file, 'w') as f:
            subprocess.run(' '.join(cmd), shell=True, stdout=f, check=True)
        
        return output_file
    
    def _export_postgresql(self, include_schema, include_data):
        """导出PostgreSQL数据库"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.temp_dir, f"{self.database.name}_{timestamp}.sql")
        
        # 构建pg_dump命令
        cmd = ['pg_dump']
        if not include_schema:
            cmd.append('--data-only')
        if not include_data:
            cmd.append('--schema-only')
        
        # 添加其他选项
        cmd.extend([
            '--clean',              # 添加删除数据库对象的命令
            '--if-exists',          # 在删除命令中添加IF EXISTS
            f'--file={output_file}',
            self.database.name
        ])
        
        # 执行导出
        subprocess.run(' '.join(cmd), shell=True, check=True)
        
        return output_file
    
    def _export_sqlite(self):
        """导出SQLite数据库"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.temp_dir, f"{self.database.name}_{timestamp}.sqlite")
        
        # 直接复制数据库文件
        db_path = f'/www/database/sqlite/{self.database.name}.db'
        shutil.copy2(db_path, output_file)
        
        return output_file
    
    def process_backup_file(self, sql_file):
        """处理备份文件（压缩、加密等）"""
        if not self.backup_settings:
            return sql_file
            
        processed_file = sql_file
        
        # 压缩文件
        if self.backup_settings.compression == 'gzip':
            processed_file = self._compress_gzip(sql_file)
        elif self.backup_settings.compression == 'zip':
            processed_file = self._compress_zip(sql_file)
        
        # 加密文件
        if self.backup_settings.encrypt_backup:
            processed_file = self._encrypt_file(processed_file)
        
        return processed_file
    
    def _compress_gzip(self, input_file):
        """使用gzip压缩文件"""
        output_file = f"{input_file}.gz"
        with open(input_file, 'rb') as f_in:
            with gzip.open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return output_file
    
    def _compress_zip(self, input_file):
        """使用zip压缩文件"""
        output_file = f"{input_file}.zip"
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(input_file, os.path.basename(input_file))
        return output_file
    
    def _encrypt_file(self, input_file):
        """加密文件（示例使用简单的XOR加密）"""
        # 在实际应用中，应使用更安全的加密方法
        output_file = f"{input_file}.enc"
        key = b'your-encryption-key'  # 应该使用安全的密钥管理
        
        with open(input_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                data = f_in.read()
                encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
                f_out.write(encrypted)
        
        return output_file
    
    def store_backup_file(self, backup_file):
        """存储备份文件到指定位置"""
        if not self.backup_settings:
            return self._store_local(backup_file)
            
        if self.backup_settings.storage_type == 'ftp':
            return self._store_ftp(backup_file)
        elif self.backup_settings.storage_type == 's3':
            return self._store_s3(backup_file)
        else:
            return self._store_local(backup_file)
    
    def _store_local(self, backup_file):
        """存储到本地"""
        backup_dir = os.path.join(settings.MEDIA_ROOT, 'backups/databases')
        os.makedirs(backup_dir, exist_ok=True)
        
        dest_file = os.path.join(backup_dir, os.path.basename(backup_file))
        shutil.copy2(backup_file, dest_file)
        
        # 返回相对于MEDIA_ROOT的路径
        return os.path.relpath(dest_file, settings.MEDIA_ROOT)
    
    def _store_ftp(self, backup_file):
        """存储到FTP服务器"""
        try:
            with FTP(self.backup_settings.ftp_host) as ftp:
                ftp.login(
                    self.backup_settings.ftp_username,
                    self.backup_settings.ftp_password
                )
                
                # 创建备份目录
                backup_path = f'/backups/{self.database.name}'
                try:
                    ftp.mkd(backup_path)
                except:
                    pass
                
                # 上传文件
                with open(backup_file, 'rb') as f:
                    ftp.storbinary(
                        f'STOR {backup_path}/{os.path.basename(backup_file)}',
                        f
                    )
                
                return f"{backup_path}/{os.path.basename(backup_file)}"
        except Exception as e:
            logger.error(f"FTP上传失败: {str(e)}")
            raise
    
    def _store_s3(self, backup_file):
        """存储到Amazon S3"""
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.backup_settings.s3_access_key,
                aws_secret_access_key=self.backup_settings.s3_secret_key
            )
            
            # 上传文件
            file_name = os.path.basename(backup_file)
            object_name = f"backups/{self.database.name}/{file_name}"
            
            s3_client.upload_file(
                backup_file,
                self.backup_settings.s3_bucket,
                object_name
            )
            
            return object_name
        except ClientError as e:
            logger.error(f"S3上传失败: {str(e)}")
            raise
    
    def cleanup_old_backups(self, keep_count):
        """清理旧的备份文件"""
        if not self.backup_settings:
            return
            
        if self.backup_settings.storage_type == 'local':
            self._cleanup_local_backups(keep_count)
        elif self.backup_settings.storage_type == 'ftp':
            self._cleanup_ftp_backups(keep_count)
        elif self.backup_settings.storage_type == 's3':
            self._cleanup_s3_backups(keep_count)
    
    def _cleanup_local_backups(self, keep_count):
        """清理本地旧备份"""
        backup_dir = os.path.join(settings.MEDIA_ROOT, 'backups/databases')
        if not os.path.exists(backup_dir):
            return
            
        # 获取所有备份文件并按修改时间排序
        files = []
        for f in os.listdir(backup_dir):
            if f.startswith(self.database.name):
                path = os.path.join(backup_dir, f)
                files.append((path, os.path.getmtime(path)))
        
        files.sort(key=lambda x: x[1], reverse=True)
        
        # 删除多余的备份
        for path, _ in files[keep_count:]:
            try:
                os.remove(path)
            except Exception as e:
                logger.error(f"删除备份文件失败: {str(e)}")
    
    def _cleanup_ftp_backups(self, keep_count):
        """清理FTP服务器上的旧备份"""
        try:
            with FTP(self.backup_settings.ftp_host) as ftp:
                ftp.login(
                    self.backup_settings.ftp_username,
                    self.backup_settings.ftp_password
                )
                
                backup_path = f'/backups/{self.database.name}'
                try:
                    files = []
                    ftp.cwd(backup_path)
                    
                    # 获取文件列表
                    def store_file(line):
                        if line.startswith(self.database.name):
                            files.append(line.split()[-1])
                    
                    ftp.retrlines('LIST', store_file)
                    
                    # 按名称排序（假设包含时间戳）
                    files.sort(reverse=True)
                    
                    # 删除多余的备份
                    for file in files[keep_count:]:
                        try:
                            ftp.delete(file)
                        except:
                            pass
                            
                except:
                    pass
        except Exception as e:
            logger.error(f"清理FTP备份失败: {str(e)}")
    
    def _cleanup_s3_backups(self, keep_count):
        """清理S3上的旧备份"""
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.backup_settings.s3_access_key,
                aws_secret_access_key=self.backup_settings.s3_secret_key
            )
            
            # 列出所有备份文件
            prefix = f"backups/{self.database.name}/"
            response = s3_client.list_objects_v2(
                Bucket=self.backup_settings.s3_bucket,
                Prefix=prefix
            )
            
            if 'Contents' in response:
                # 按最后修改时间排序
                files = sorted(
                    response['Contents'],
                    key=lambda x: x['LastModified'],
                    reverse=True
                )
                
                # 删除多余的备份
                for obj in files[keep_count:]:
                    try:
                        s3_client.delete_object(
                            Bucket=self.backup_settings.s3_bucket,
                            Key=obj['Key']
                        )
                    except:
                        pass
                        
        except ClientError as e:
            logger.error(f"清理S3备份失败: {str(e)}")
    
    def import_database(self, import_file, clear_database=False):
        """导入数据库"""
        try:
            # 处理压缩文件
            if import_file.name.endswith('.gz'):
                processed_file = self._decompress_gzip(import_file)
            elif import_file.name.endswith('.zip'):
                processed_file = self._decompress_zip(import_file)
            else:
                processed_file = import_file
            
            # 根据数据库类型执行导入
            if self.database.db_type == 'mysql':
                return self._import_mysql(processed_file, clear_database)
            elif self.database.db_type == 'postgresql':
                return self._import_postgresql(processed_file, clear_database)
            elif self.database.db_type == 'sqlite':
                return self._import_sqlite(processed_file)
            else:
                raise ValueError(f"不支持的数据库类型: {self.database.db_type}")
        except Exception as e:
            logger.error(f"导入数据库失败: {str(e)}")
            raise
    
    def _decompress_gzip(self, gzip_file):
        """解压gzip文件"""
        output_file = os.path.join(self.temp_dir, os.path.splitext(gzip_file.name)[0])
        with gzip.open(gzip_file.temporary_file_path(), 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return output_file
    
    def _decompress_zip(self, zip_file):
        """解压zip文件"""
        with zipfile.ZipFile(zip_file.temporary_file_path(), 'r') as zip_ref:
            # 获取第一个.sql文件
            sql_files = [f for f in zip_ref.namelist() if f.endswith('.sql')]
            if not sql_files:
                raise ValueError("ZIP文件中未找到SQL文件")
            
            output_file = os.path.join(self.temp_dir, sql_files[0])
            zip_ref.extract(sql_files[0], self.temp_dir)
            return output_file
    
    def _import_mysql(self, sql_file, clear_database):
        """导入MySQL数据库"""
        try:
            if clear_database:
                # 清空数据库
                subprocess.run(
                    f'mysql -e "DROP DATABASE IF EXISTS {self.database.name}; CREATE DATABASE {self.database.name};"',
                    shell=True,
                    check=True
                )
            
            # 导入数据
            subprocess.run(
                f'mysql {self.database.name} < {sql_file}',
                shell=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"MySQL导入失败: {str(e)}")
            raise
    
    def _import_postgresql(self, sql_file, clear_database):
        """导入PostgreSQL数据库"""
        try:
            if clear_database:
                # 清空数据库
                subprocess.run(
                    f'dropdb --if-exists {self.database.name} && createdb {self.database.name}',
                    shell=True,
                    check=True
                )
            
            # 导入数据
            subprocess.run(
                f'psql {self.database.name} < {sql_file}',
                shell=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"PostgreSQL导入失败: {str(e)}")
            raise
    
    def _import_sqlite(self, db_file):
        """导入SQLite数据库"""
        try:
            db_path = f'/www/database/sqlite/{self.database.name}.db'
            shutil.copy2(db_file, db_path)
            os.chmod(db_path, 0o666)
            return True
        except Exception as e:
            logger.error(f"SQLite导入失败: {str(e)}")
            raise 