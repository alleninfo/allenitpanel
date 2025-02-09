import subprocess
import re

def get_installed_php_versions():
    """
    获取系统中已安装的PHP版本
    返回格式如: ['7.4', '8.0', '8.1']
    """
    try:
        # 使用which命令查找php-fpm服务
        result = subprocess.run('find /usr/sbin -name "php-fpm*"', shell=True, capture_output=True, text=True)
        versions = []
        for line in result.stdout.splitlines():
            # 使用正则表达式提取版本号
            match = re.search(r'php-fpm(\d+\.\d+)', line)
            if match:
                version = match.group(1)
                if version not in versions:
                    versions.append(version)
        return sorted(versions)
    except Exception as e:
        print(f"获取PHP版本时出错: {str(e)}")
        return [] 