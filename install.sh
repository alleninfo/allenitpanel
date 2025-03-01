#!/bin/bash

echo "开始安装 AllenITPanel..."

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then 
    echo "请使用root用户运行此脚本"
    exit 1
fi

# 创建虚拟环境
echo "创建 Python 虚拟环境..."
python3 -m venv venv
source venv/bin/activate

# 安装依赖
echo "安装依赖..."
pip install -r requirements.txt
pip install gunicorn

# 创建必要的目录
echo "创建必要的目录..."
mkdir -p static media logs websites/static

# 收集静态文件
echo "收集静态文件..."
python manage.py collectstatic --noinput

# 执行数据库迁移
echo "执行数据库迁移..."
python manage.py migrate

# 创建管理员账号
echo "创建管理员账号..."
DJANGO_SUPERUSER_USERNAME="admin"
DJANGO_SUPERUSER_EMAIL="admin@example.com"
DJANGO_SUPERUSER_PASSWORD="Admin123456"

echo "使用以下默认管理员账号："
echo "用户名: $DJANGO_SUPERUSER_USERNAME"
echo "密码: $DJANGO_SUPERUSER_PASSWORD"
echo "邮箱: $DJANGO_SUPERUSER_EMAIL"

# 导出环境变量
export DJANGO_SUPERUSER_USERNAME
export DJANGO_SUPERUSER_EMAIL
export DJANGO_SUPERUSER_PASSWORD

python manage.py createsuperuser --noinput

# 设置文件权限
echo "设置文件权限..."
chmod +x manage.py
chmod 755 -R static media logs

# 配置系统服务
echo "配置系统服务..."
systemctl daemon-reload
systemctl enable allenitpanel
systemctl start allenitpanel

echo "安装完成！"
echo "AllenITPanel 已经在后台启动，访问地址: http://服务器IP:8000"
echo "管理员登录信息："
echo "  用户名: $DJANGO_SUPERUSER_USERNAME"
echo "  密码: $DJANGO_SUPERUSER_PASSWORD"
echo "  后台地址: http://服务器IP:8000/admin"
echo ""
echo "查看服务状态: systemctl status allenitpanel"
echo "查看服务日志: journalctl -u allenitpanel -f" 