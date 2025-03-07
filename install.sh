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
              ;;
        "ubuntu"|"debian")
            apt update
            apt install -y build-essential python3 python3-pip python3-dev git
            # 安装 Caddy
            apt install -y debian-keyring debian-archive-keyring apt-transport-https
             
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
pip install -r requirements.txt

  

# 创建 wsgi.py
echo -e "${GREEN}创建 WSGI 配置...${NC}"
cat > allenitpanel/wsgi.py << EOL
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'setting_panel.settings')
application = get_wsgi_application()
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
Environment="DJANGO_SETTINGS_MODULE=setting_panel.settings"
ExecStart=$PROJECT_DIR/venv/bin/gunicorn setting_panel.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile logs/access.log --error-logfile logs/error.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
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
 systemctl restart allenitpanel
 
echo -e "${GREEN}安装完成！${NC}"
echo -e "${GREEN}管理员账户: admin${NC}"
echo -e "${GREEN}管理员密码: admin123${NC}"
echo -e "${GREEN}请通过以下地址访问:${NC}"
echo -e "${GREEN}http://服务器IP${NC}"
echo -e "${YELLOW}请及时修改管理员密码！${NC}"

# 显示服务状态
echo -e "${GREEN}服务状态:${NC}"
systemctl status allenitpanel | cat
  