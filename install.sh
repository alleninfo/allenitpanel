#!/bin/bash

# 设置颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用root用户运行此脚本${NC}"
    exit 1
fi

# 检测系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}无法检测操作系统类型${NC}"
    exit 1
fi

echo -e "${GREEN}检测到操作系统: $OS $VERSION${NC}"

# 安装基础依赖
install_dependencies() {
    case $OS in
        "centos"|"rhel")
            yum update -y
            yum groupinstall -y "Development Tools"
            yum install -y python3 python3-pip python3-devel git yum-utils
            yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/g/caddy/caddy/repo/epel-7/group_caddy-caddy-epel-7.repo
            yum install -y caddy
            ;;
        "ubuntu"|"debian")
            apt update
            apt install -y build-essential python3 python3-pip python3-dev git
            # 安装 Caddy
            apt install -y debian-keyring debian-archive-keyring apt-transport-https
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
            apt update
            apt install -y caddy
            ;;
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            exit 1
            ;;
    esac
}

# 执行安装依赖
install_dependencies

# 创建项目目录
PROJECT_DIR="/opt/allenitpanel"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# 创建虚拟环境
echo -e "${GREEN}创建Python虚拟环境...${NC}"
python3 -m venv venv
source venv/bin/activate

# 安装Python依赖
echo -e "${GREEN}安装Python依赖...${NC}"
pip install --upgrade pip
pip install django gunicorn python-dotenv django-cors-headers

# 创建Django项目结构
echo -e "${GREEN}创建Django项目...${NC}"
django-admin startproject allenitpanel .
python manage.py startapp websites

# 配置settings.py
echo -e "${GREEN}配置Django设置...${NC}"
cat > allenitpanel/settings.py << EOL
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'django-insecure-$(openssl rand -base64 32)'

DEBUG = False
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'websites',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'allenitpanel.urls'
WSGI_APPLICATION = 'allenitpanel.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
EOL

# 创建 wsgi.py
echo -e "${GREEN}创建 WSGI 配置...${NC}"
cat > allenitpanel/wsgi.py << EOL
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'allenitpanel.settings')
application = get_wsgi_application()
EOL

# 创建 urls.py
echo -e "${GREEN}创建 URL 配置...${NC}"
cat > allenitpanel/urls.py << EOL
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
EOL

# 创建目录
mkdir -p logs media static

# 配置systemd服务
echo -e "${GREEN}配置systemd服务...${NC}"
cat > /etc/systemd/system/allenitpanel.service << EOL
[Unit]
Description=AllenITPanel Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Environment="PYTHONPATH=$PROJECT_DIR"
Environment="DJANGO_SETTINGS_MODULE=allenitpanel.settings"
ExecStart=$PROJECT_DIR/venv/bin/gunicorn allenitpanel.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile logs/access.log --error-logfile logs/error.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

# 配置 Caddy
echo -e "${GREEN}配置Caddy...${NC}"
cat > /etc/caddy/Caddyfile << EOL
:80 {
    root * $PROJECT_DIR
    @notStatic {
        not path /static/* /media/*
    }
    reverse_proxy @notStatic localhost:8000
    file_server /static/* {
        root $PROJECT_DIR
    }
    file_server /media/* {
        root $PROJECT_DIR
    }
    encode gzip
    log {
        output file $PROJECT_DIR/logs/caddy.log
    }
}
EOL

# 初始化数据库
echo -e "${GREEN}初始化数据库...${NC}"
python manage.py makemigrations
python manage.py migrate

# 创建超级用户
echo -e "${YELLOW}创建管理员账户${NC}"
echo "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin123')" | python manage.py shell

# 收集静态文件
python manage.py collectstatic --noinput

# 设置权限
chown -R root:root $PROJECT_DIR
chmod -R 755 $PROJECT_DIR

# 启动服务
echo -e "${GREEN}启动服务...${NC}"
systemctl daemon-reload
systemctl enable allenitpanel
systemctl enable caddy
systemctl restart allenitpanel
systemctl restart caddy

echo -e "${GREEN}安装完成！${NC}"
echo -e "${GREEN}管理员账户: admin${NC}"
echo -e "${GREEN}管理员密码: admin123${NC}"
echo -e "${GREEN}请通过以下地址访问:${NC}"
echo -e "${GREEN}http://服务器IP${NC}"
echo -e "${YELLOW}请及时修改管理员密码！${NC}"

# 显示服务状态
echo -e "${GREEN}服务状态:${NC}"
systemctl status allenitpanel | cat
systemctl status caddy | cat
 