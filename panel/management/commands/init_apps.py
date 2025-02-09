from django.core.management.base import BaseCommand
from panel.models import Application

class Command(BaseCommand):
    help = '初始化应用商店应用'

    def handle(self, *args, **options):
        # PHP
        self.create_php_apps()
        # MySQL
        self.create_mysql_apps()
        # Nginx
        self.create_nginx_apps()
        # Redis
        self.create_redis_apps()
        # phpMyAdmin
        self.create_phpmyadmin_apps()
        
        self.stdout.write(self.style.SUCCESS('应用初始化完成'))

    def create_php_apps(self):
        php_versions = ['7.4', '8.0', '8.1', '8.2']
        for version in php_versions:
            for os in ['centos8', 'centos9']:
                Application.objects.get_or_create(
                    name='PHP',
                    version=version,
                    os_version=os,
                    defaults={
                        'category': 'language',
                        'description': f'PHP {version} 运行环境',
                        'install_script': self.get_php_install_script(version, os),
                        'uninstall_script': self.get_php_uninstall_script(os),
                        'homepage': 'https://www.php.net/'
                    }
                )

    def create_mysql_apps(self):
        mysql_versions = ['5.7', '8.0']
        for version in mysql_versions:
            for os in ['centos8', 'centos9']:
                Application.objects.get_or_create(
                    name='MySQL',
                    version=version,
                    os_version=os,
                    defaults={
                        'category': 'database',
                        'description': f'MySQL {version} 数据库服务器',
                        'install_script': self.get_mysql_install_script(version, os),
                        'uninstall_script': self.get_mysql_uninstall_script(os),
                        'homepage': 'https://www.mysql.com/'
                    }
                )

    def create_nginx_apps(self):
        nginx_versions = ['1.20', '1.22', '1.24']
        for version in nginx_versions:
            for os in ['centos8', 'centos9']:
                Application.objects.get_or_create(
                    name='Nginx',
                    version=version,
                    os_version=os,
                    defaults={
                        'category': 'web',
                        'description': f'Nginx {version} Web服务器',
                        'install_script': self.get_nginx_install_script(version, os),
                        'uninstall_script': self.get_nginx_uninstall_script(os),
                        'homepage': 'https://nginx.org/'
                    }
                )

    def create_redis_apps(self):
        redis_versions = ['6.2', '7.0']
        for version in redis_versions:
            for os in ['centos8', 'centos9']:
                Application.objects.get_or_create(
                    name='Redis',
                    version=version,
                    os_version=os,
                    defaults={
                        'category': 'cache',
                        'description': f'Redis {version} 缓存服务器',
                        'install_script': self.get_redis_install_script(version, os),
                        'uninstall_script': self.get_redis_uninstall_script(os),
                        'homepage': 'https://redis.io/'
                    }
                )

    def create_phpmyadmin_apps(self):
        pma_versions = ['5.2.1']
        for version in pma_versions:
            for os in ['centos8', 'centos9']:
                Application.objects.get_or_create(
                    name='phpMyAdmin',
                    version=version,
                    os_version=os,
                    defaults={
                        'category': 'tool',
                        'description': f'phpMyAdmin {version} MySQL管理工具',
                        'install_script': self.get_phpmyadmin_install_script(version, os),
                        'uninstall_script': self.get_phpmyadmin_uninstall_script(os),
                        'homepage': 'https://www.phpmyadmin.net/'
                    }
                )

    def get_php_install_script(self, version, os):
        if os == 'centos8':
            return f'''
#!/bin/bash
# 安装PHP {version} 在CentOS 8
dnf -y install epel-release
dnf -y install dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm
dnf -y module reset php
dnf -y module enable php:remi-{version}
dnf -y install php php-cli php-fpm php-mysqlnd php-zip php-devel php-gd php-mcrypt php-mbstring php-curl php-xml php-pear php-bcmath php-json
systemctl enable --now php-fpm
'''
        else:  # centos9
            return f'''
#!/bin/bash
# 安装PHP {version} 在CentOS 9
dnf -y install epel-release
dnf -y install dnf-utils http://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf -y module reset php
dnf -y module enable php:remi-{version}
dnf -y install php php-cli php-fpm php-mysqlnd php-zip php-devel php-gd php-mcrypt php-mbstring php-curl php-xml php-pear php-bcmath php-json
systemctl enable --now php-fpm
'''

    def get_mysql_install_script(self, version, os):
        if version == '5.7':
            return f'''
#!/bin/bash
# 安装MySQL {version} 在{os}
dnf -y install mysql-server
systemctl enable --now mysqld
mysql_secure_installation
'''
        else:  # 8.0
            return f'''
#!/bin/bash
# 安装MySQL {version} 在{os}
dnf -y install mysql-server
systemctl enable --now mysqld
mysql_secure_installation
'''

    def get_nginx_install_script(self, version, os):
        return f'''
#!/bin/bash
# 安装Nginx {version} 在{os}
dnf -y install nginx
systemctl enable --now nginx
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
'''

    def get_redis_install_script(self, version, os):
        return f'''
#!/bin/bash
# 安装Redis {version} 在{os}
dnf -y install redis
systemctl enable --now redis
firewall-cmd --permanent --add-port=6379/tcp
firewall-cmd --reload
'''

    def get_phpmyadmin_install_script(self, version, os):
        return f'''
#!/bin/bash
# 安装phpMyAdmin {version} 在{os}
dnf -y install phpMyAdmin
systemctl restart httpd
'''

    def get_php_uninstall_script(self, os):
        return '''
#!/bin/bash
systemctl stop php-fpm
dnf -y remove php*
'''

    def get_mysql_uninstall_script(self, os):
        return '''
#!/bin/bash
systemctl stop mysqld
dnf -y remove mysql*
rm -rf /var/lib/mysql
'''

    def get_nginx_uninstall_script(self, os):
        return '''
#!/bin/bash
systemctl stop nginx
dnf -y remove nginx
'''

    def get_redis_uninstall_script(self, os):
        return '''
#!/bin/bash
systemctl stop redis
dnf -y remove redis
'''

    def get_phpmyadmin_uninstall_script(self, os):
        return '''
#!/bin/bash
dnf -y remove phpMyAdmin
''' 