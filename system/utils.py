import os
import psutil
import platform
import subprocess
import shutil
from datetime import datetime

def get_system_info():
    """获取系统基本信息"""
    try:
        info = {
            'os': f"{platform.system()} {platform.release()}",
            'hostname': platform.node(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'kernel': platform.version(),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        }
        return info
    except Exception as e:
        return {'error': str(e)}

def get_cpu_info():
    """获取CPU信息"""
    try:
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'total_cores': psutil.cpu_count(logical=True),
            'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else None,
            'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else None,
            'cpu_usage_per_core': [percentage for percentage in psutil.cpu_percent(percpu=True)],
            'total_cpu_usage': psutil.cpu_percent(),
        }
        return cpu_info
    except Exception as e:
        return {'error': str(e)}

def get_memory_info():
    """获取内存信息"""
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_info = {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'free': memory.free,
            'percent': memory.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_free': swap.free,
            'swap_percent': swap.percent,
        }
        return memory_info
    except Exception as e:
        return {'error': str(e)}

def get_disk_info():
    """获取磁盘信息"""
    try:
        disk_info = []
        for partition in psutil.disk_partitions():
            if os.name == 'nt':
                if 'cdrom' in partition.opts or partition.fstype == '':
                    continue
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent,
            })
        return disk_info
    except Exception as e:
        return {'error': str(e)}

def get_network_info():
    """获取网络信息"""
    try:
        network_info = {
            'interfaces': {},
            'connections': len(psutil.net_connections()),
        }
        
        # 获取网络接口信息
        for interface, addresses in psutil.net_if_addrs().items():
            network_info['interfaces'][interface] = []
            for addr in addresses:
                network_info['interfaces'][interface].append({
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'family': str(addr.family),
                })
        
        # 获取网络IO统计
        net_io = psutil.net_io_counters()
        network_info['io_stats'] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'error_in': net_io.errin,
            'error_out': net_io.errout,
            'drop_in': net_io.dropin,
            'drop_out': net_io.dropout,
        }
        
        return network_info
    except Exception as e:
        return {'error': str(e)}

def get_process_list():
    """获取进程列表"""
    try:
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                process_list.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent'],
                    'status': proc.info['status'],
                    'create_time': datetime.fromtimestamp(proc.info['create_time']).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return sorted(process_list, key=lambda x: x['cpu_percent'], reverse=True)
    except Exception as e:
        return {'error': str(e)}

def kill_process(pid):
    """结束进程"""
    try:
        process = psutil.Process(pid)
        process.terminate()
        return True
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        try:
            # 尝试使用系统命令强制结束进程
            if os.name == 'nt':
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], check=True)
            else:
                subprocess.run(['kill', '-9', str(pid)], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

def get_service_status(service_name):
    """获取服务状态"""
    try:
        if os.name == 'nt':
            result = subprocess.run(['sc', 'query', service_name], capture_output=True, text=True)
            return 'RUNNING' in result.stdout
        else:
            result = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
    except Exception:
        return False

def control_service(service_name, action):
    """控制系统服务"""
    try:
        if os.name == 'nt':
            if action == 'start':
                subprocess.run(['net', 'start', service_name], check=True)
            elif action == 'stop':
                subprocess.run(['net', 'stop', service_name], check=True)
            elif action == 'restart':
                subprocess.run(['net', 'stop', service_name], check=True)
                subprocess.run(['net', 'start', service_name], check=True)
        else:
            subprocess.run(['systemctl', action, service_name], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_system_logs(log_type='system', lines=100):
    """获取系统日志"""
    try:
        if os.name == 'nt':
            # Windows系统使用PowerShell获取事件日志
            if log_type == 'system':
                cmd = ['powershell', 'Get-EventLog', '-LogName', 'System', '-Newest', str(lines)]
            elif log_type == 'security':
                cmd = ['powershell', 'Get-EventLog', '-LogName', 'Security', '-Newest', str(lines)]
            else:
                cmd = ['powershell', 'Get-EventLog', '-LogName', 'Application', '-Newest', str(lines)]
        else:
            # Linux系统直接读取日志文件
            if log_type == 'system':
                cmd = ['journalctl', '-n', str(lines)]
            elif log_type == 'security':
                cmd = ['journalctl', '-n', str(lines), '_TRANSPORT=audit']
            else:
                cmd = ['journalctl', '-n', str(lines), '_TRANSPORT=syslog']
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [str(e)]

def get_system_updates():
    """检查系统更新"""
    try:
        if os.name == 'nt':
            # Windows系统使用PowerShell检查更新
            cmd = ['powershell', 'Get-WUList']
        else:
            # Linux系统检查更新
            if os.path.exists('/usr/bin/apt'):
                cmd = ['apt', 'list', '--upgradable']
            elif os.path.exists('/usr/bin/dnf'):
                cmd = ['dnf', 'check-update']
            else:
                cmd = ['yum', 'check-update']
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [str(e)]

def get_disk_io():
    """获取磁盘IO统计"""
    try:
        disk_io = psutil.disk_io_counters()
        return {
            'read_bytes': disk_io.read_bytes,
            'write_bytes': disk_io.write_bytes,
            'read_count': disk_io.read_count,
            'write_count': disk_io.write_count,
            'read_time': disk_io.read_time,
            'write_time': disk_io.write_time,
        }
    except Exception as e:
        return {'error': str(e)} 