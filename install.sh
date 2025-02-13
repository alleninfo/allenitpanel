#!/bin/bash

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 定义项目路径和名称
PROJECT_PATH="/opt/panel"
PROJECT_NAME="panel"
VENV_PATH="${PROJECT_PATH}/venv"
SUPERVISOR_CONF="/etc/supervisor/conf.d/${PROJECT_NAME}.conf"
NGINX_CONF="/etc/nginx/conf.d/${PROJECT_NAME}.conf"

# 检测系统类型
get_system_type() {
    if [ -f /etc/redhat-release ]; then
        echo "centos"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}
mkdir -p ${PROJECT_PATH}
# 安装依赖
install_dependencies() {
    echo -e "${GREEN}正在安装系统依赖...${NC}"
    
    SYSTEM_TYPE=$(get_system_type)
    
    case $SYSTEM_TYPE in
        "centos")
            # 安装EPEL源
            yum install -y epel-release
            
            # 安装Python3和其他依赖
            yum install -y python3 python3-pip nginx redis git tar wget curl unzip
            
            # 安装supervisor
            pip3 install supervisor
            
            # 创建supervisor配置目录
            mkdir -p /etc/supervisor/conf.d
            
            # 创建supervisor配置文件
            if [ ! -f /etc/supervisord.conf ]; then
                echo -e "${GREEN}正在创建supervisor配置文件...${NC}"
                echo_supervisord_conf > /etc/supervisord.conf
                # 添加include配置
                echo "[include]" >> /etc/supervisord.conf
                echo "files = /etc/supervisor/conf.d/*.conf" >> /etc/supervisord.conf
            fi
            
            # 创建supervisor服务
            cat > /etc/systemd/system/supervisord.service << EOF
[Unit]
Description=Supervisor daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/supervisord -c /etc/supervisord.conf
ExecStop=/usr/local/bin/supervisorctl shutdown
ExecReload=/usr/local/bin/supervisorctl reload
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF
            
            # 启动服务
            systemctl daemon-reload
            systemctl enable --now supervisord
            systemctl enable --now nginx
            systemctl enable --now redis
            
            # 配置防火墙
            if command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-service=http
                firewall-cmd --permanent --add-service=https
                firewall-cmd --reload
            fi
            
            # 关闭SELinux
            if [ -f /etc/selinux/config ]; then
                setenforce 0
                sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
            fi
            ;;
            
        "debian")
            apt-get update
            apt-get install -y python3 python3-venv python3-pip nginx supervisor redis-server
            systemctl enable --now supervisor
            systemctl enable --now nginx
            systemctl enable --now redis-server
            ;;
            
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            exit 1
            ;;
    esac
}

# 创建虚拟环境并安装依赖
setup_virtualenv() {
    echo -e "${GREEN}正在设置Python虚拟环境...${NC}"
    python3 -m venv ${VENV_PATH}
    source ${VENV_PATH}/bin/activate
    pip install --upgrade pip
    wget https://gitee.com/allenit/allenpanel/repository/archive/master.zip
    unzip master.zip -C ${PROJECT_PATH}
    mv allenpanel-master/* ${PROJECT_PATH}
    rm -rf allenpanel-master
    cd ${PROJECT_PATH}
    cat > /root/.pip/pip.conf << EOF
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
[install]
trusted-host=pypi.tuna.tsinghua.edu.cn
EOF

    pip install -r ${PROJECT_PATH}/requirements.txt
}

# 配置Supervisor
setup_supervisor() {
    echo -e "${GREEN}正在配置Supervisor...${NC}"
    mkdir -p /etc/supervisor/conf.d
    
    cat > ${SUPERVISOR_CONF} << EOF
[program:${PROJECT_NAME}]
directory=${PROJECT_PATH}
command=${VENV_PATH}/bin/python manage.py runserver 0.0.0.0:8000
user=root
autostart=true
autorestart=true
stderr_logfile=/var/log/${PROJECT_NAME}_err.log
stdout_logfile=/var/log/${PROJECT_NAME}_out.log
EOF

    SYSTEM_TYPE=$(get_system_type)
    if [ "$SYSTEM_TYPE" = "centos" ]; then
        supervisorctl reread
        supervisorctl update
        supervisorctl restart ${PROJECT_NAME}
    else
        supervisorctl reread
        supervisorctl update
        supervisorctl restart ${PROJECT_NAME}
    fi
}

# 配置Nginx
setup_nginx() {
    echo -e "${GREEN}正在配置Nginx...${NC}"
    cat > ${NGINX_CONF} << EOF
server {
    listen 80;
    server_name _;

    location /static/ {
        alias ${PROJECT_PATH}/static/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

    SYSTEM_TYPE=$(get_system_type)
    if [ "$SYSTEM_TYPE" = "centos" ]; then
        nginx -t && systemctl restart nginx
    else
        nginx -t && systemctl restart nginx
    fi
}

# 安装功能
install() {
    check_root
    
    echo -e "${GREEN}开始安装...${NC}"
    
    # 检查项目目录是否存在
    if [ ! -d "$PROJECT_PATH" ]; then
        echo -e "${RED}错误: 项目目录 ${PROJECT_PATH} 不存在${NC}"
        exit 1
    fi

    install_dependencies
    setup_virtualenv
    
    # 执行数据库迁移
    source ${VENV_PATH}/bin/activate
    python ${PROJECT_PATH}/manage.py migrate
    python ${PROJECT_PATH}/manage.py collectstatic --noinput
    
    setup_supervisor
    setup_nginx
    
    echo -e "${GREEN}安装完成！${NC}"
    echo -e "${GREEN}请使用浏览器访问 http://服务器IP 来访问系统${NC}"
}

# 卸载功能
uninstall() {
    check_root
    
    echo -e "${YELLOW}开始卸载...${NC}"
    
    SYSTEM_TYPE=$(get_system_type)
    
    # 停止并删除supervisor配置
    supervisorctl stop ${PROJECT_NAME}
    rm -f ${SUPERVISOR_CONF}
    supervisorctl reread
    
    # 删除nginx配置
    rm -f ${NGINX_CONF}
    
    if [ "$SYSTEM_TYPE" = "centos" ]; then
        nginx -t && systemctl restart nginx
        
        # 删除服务
        systemctl disable --now supervisord
        rm -f /etc/systemd/system/supervisord.service
        systemctl daemon-reload
    else
        nginx -t && systemctl restart nginx
    fi
    
    # 删除项目文件
    rm -rf ${PROJECT_PATH}
    
    echo -e "${GREEN}卸载完成！${NC}"
}

# 重置管理员密码
reset_admin_password() {
    check_root
    
    if [ ! -d "$PROJECT_PATH" ]; then
        echo -e "${RED}错误: 系统未安装，请先安装系统${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}请输入新的管理员密码: ${NC}"
    read -s password
    echo
    
    source ${VENV_PATH}/bin/activate
    python ${PROJECT_PATH}/manage.py shell << EOF
from django.contrib.auth.models import User
admin = User.objects.get(username='admin')
admin.set_password('${password}')
admin.save()
EOF
    
    echo -e "${GREEN}管理员密码已重置！${NC}"
}

# 显示系统信息
show_system_info() {
    SYSTEM_TYPE=$(get_system_type)
    echo -e "${GREEN}系统信息：${NC}"
    echo "操作系统类型: $SYSTEM_TYPE"
    
    if [ -d "$PROJECT_PATH" ]; then
        echo "安装状态: 已安装"
        echo "安装路径: $PROJECT_PATH"
        
        if systemctl is-active --quiet nginx; then
            echo "Nginx状态: 运行中"
        else
            echo "Nginx状态: 未运行"
        fi
        
        if [ "$SYSTEM_TYPE" = "centos" ]; then
            if systemctl is-active --quiet supervisord; then
                echo "Supervisor状态: 运行中"
            else
                echo "Supervisor状态: 未运行"
            fi
        else
            if systemctl is-active --quiet supervisor; then
                echo "Supervisor状态: 运行中"
            else
                echo "Supervisor状态: 未运行"
            fi
        fi
    else
        echo "安装状态: 未安装"
    fi
}

# 显示菜单
show_menu() {
    clear
    echo -e "${GREEN}=============================${NC}"
    echo -e "${GREEN}      面板管理系统部署脚本    ${NC}"
    echo -e "${GREEN}=============================${NC}"
    echo
    show_system_info
    echo
    echo -e "${GREEN}1.${NC} 安装系统"
    echo -e "${GREEN}2.${NC} 卸载系统"
    echo -e "${GREEN}3.${NC} 重置管理员密码"
    echo -e "${GREEN}4.${NC} 帮助信息"
    echo -e "${GREEN}0.${NC} 退出"
    echo
    echo -e "${YELLOW}请输入选项 [0-4]: ${NC}"
}

# 显示帮助信息
show_help() {
    clear
    echo -e "${GREEN}系统说明：${NC}"
    echo "1. 本脚本支持 CentOS 和 Ubuntu/Debian 系统"
    echo "2. 安装过程会自动配置必要的环境和依赖"
    echo "3. 安装完成后可通过 http://服务器IP 访问系统"
    echo "4. 如遇问题请查看相关日志文件"
    echo
    echo -e "${GREEN}文件位置：${NC}"
    echo "- 项目目录: ${PROJECT_PATH}"
    echo "- Supervisor配置: ${SUPERVISOR_CONF}"
    echo "- Nginx配置: ${NGINX_CONF}"
    echo "- 错误日志: /var/log/${PROJECT_NAME}_err.log"
    echo "- 输出日志: /var/log/${PROJECT_NAME}_out.log"
    echo
    echo -e "${GREEN}常见问题：${NC}"
    echo "1. 如果访问出现502错误，请检查supervisor日志"
    echo "2. 如果静态文件无法访问，请检查nginx配置和权限"
    echo "3. 如果数据库报错，请检查数据库配置和迁移状态"
    echo
    echo -e "${GREEN}系统要求：${NC}"
    echo "- Python 3.6+"
    echo "- 2GB+ RAM"
    echo "- 10GB+ 磁盘空间"
}

# 主程序
main() {
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                clear
                echo -e "${YELLOW}准备安装系统...${NC}"
                echo -e "${YELLOW}请确认是否继续？(y/n): ${NC}"
                read -r confirm
                if [[ $confirm == [Yy] ]]; then
                    install
                fi
                echo -e "${GREEN}按回车键返回主菜单${NC}"
                read -r
                ;;
                
            2)
                clear
                echo -e "${RED}警告: 卸载将删除所有相关文件和数据！${NC}"
                echo -e "${YELLOW}请确认是否继续？(y/n): ${NC}"
                read -r confirm
                if [[ $confirm == [Yy] ]]; then
                    uninstall
                fi
                echo -e "${GREEN}按回车键返回主菜单${NC}"
                read -r
                ;;
                
            3)
                clear
                echo -e "${YELLOW}准备重置管理员密码...${NC}"
                reset_admin_password
                echo -e "${GREEN}按回车键返回主菜单${NC}"
                read -r
                ;;
                
            4)
                show_help
                echo -e "${GREEN}按回车键返回主菜单${NC}"
                read -r
                ;;
                
            0)
                clear
                echo -e "${GREEN}感谢使用！再见！${NC}"
                exit 0
                ;;
                
            *)
                echo -e "${RED}无效的选项，请重新选择${NC}"
                sleep 2
                ;;
        esac
    done
}

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
    exit 1
fi

# 运行主程序
main