#!/bin/bash

# 设置颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 设置安装目录
TARGET_DIR="/opt/allenpanel"

# 检测操作系统类型和版本
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
        if [ "$OS" = "rocky" ]; then
            OS="centos"
            echo -e "${GREEN}检测到 Rocky Linux，将作为 CentOS ${VERSION_ID} 处理${NC}"
        fi
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    else
        OS="unknown"
    fi
    echo -e "${GREEN}检测到操作系统: $OS ${VERSION_ID}${NC}"
}

# 安装依赖
install_dependencies() {
    echo -e "${GREEN}正在安装必要组件...${NC}"
    case $OS in
        "ubuntu"|"debian")
            sudo apt-get update
            sudo apt-get install -y wget vim unzip tar git nginx python3-venv python3-pip
            ;;
        "centos")
            if [ "$VERSION_ID" = "8" ]; then
                # 配置 CentOS 8 vault源
                sudo mv /etc/yum.repos.d/CentOS-* /tmp/ 2>/dev/null
                sudo curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-vault-8.5.2111.repo
                sudo dnf clean all
                sudo dnf makecache
                sudo dnf -y install epel-release
                sudo dnf -y install wget vim unzip tar git nginx python3-devel
            elif [ "$VERSION_ID" = "9" ]; then
                # 配置 CentOS Stream 9 源
                sudo dnf -y install centos-release-stream
                sudo dnf -y install epel-release
                sudo dnf config-manager --set-enabled crb
                sudo dnf clean all
                sudo dnf makecache
                sudo dnf -y install wget vim unzip tar git nginx python3-devel
            else
                sudo yum -y install epel-release
                sudo yum -y install wget vim unzip tar git nginx python3-devel
            fi
            ;;
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            exit 1
            ;;
    esac

    # 验证必要组件是否安装成功
    for cmd in wget vim unzip tar git; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}错误：$cmd 安装失败${NC}"
            exit 1
        fi
    done
}

# 安装面板
install_panel() {
    echo -e "${GREEN}开始安装Web面板...${NC}"
    
    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    # 下载源码
    wget https://gitee.com/allenit/allenpanel/repository/archive/master.zip
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败${NC}"
        exit 1
    fi

    # 解压文件
    unzip master.zip
    if [ $? -ne 0 ]; then
        echo -e "${RED}解压失败${NC}"
        exit 1
    fi

    # 创建目标目录
    sudo mkdir -p "$TARGET_DIR"
    sudo mv allenpanel-master/* "$TARGET_DIR/"

    # 创建虚拟环境
    cd "$TARGET_DIR"
    python3 -m venv venv
    source venv/bin/activate

    # 配置pip源
    mkdir -p ~/.pip
    cat > ~/.pip/pip.conf << EOF
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
[install]
trusted-host=pypi.tuna.tsinghua.edu.cn
EOF

    # 安装依赖
    pip install -r requirement.txt
    pip install gunicorn

    # 配置Nginx
    setup_nginx

    # 配置Gunicorn服务
    setup_gunicorn

    # 清理临时文件
    cd
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}安装完成！${NC}"
}

# 卸载面板
uninstall_panel() {
    echo -e "${RED}开始卸载Web面板...${NC}"
    
    # 停止服务
    systemctl stop allenpanel
    systemctl disable allenpanel
    
    # 删除服务文件
    rm -f /etc/systemd/system/allenpanel.service
    
    # 删除Nginx配置
    rm -f /etc/nginx/conf.d/allenpanel.conf
    
    # 删除安装目录
    rm -rf "$TARGET_DIR"
    
    # 重载服务
    systemctl daemon-reload
    systemctl restart nginx
    
    echo -e "${GREEN}卸载完成！${NC}"
}

# 修改管理员密码
change_admin_password() {
    echo -e "${GREEN}修改管理员密码...${NC}"
    cd "$TARGET_DIR"
    source venv/bin/activate
    python manage.py changepassword admin
}

# 重启面板服务
restart_panel() {
    echo -e "${GREEN}重启面板服务...${NC}"
    systemctl restart allenpanel
    systemctl restart nginx
    echo -e "${GREEN}服务已重启${NC}"
}

# 配置Nginx
setup_nginx() {
    cat > /etc/nginx/conf.d/allenpanel.conf << EOF
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/allenpanel_access.log;
    error_log /var/log/nginx/allenpanel_error.log;

    client_max_body_size 100M;
    
    location /static/ {
        alias /opt/allenpanel/static/;
        expires 30d;
        access_log off;
    }

    location /media/ {
        alias /opt/allenpanel/media/;
        expires 30d;
        access_log off;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}
EOF

    # 创建静态文件目录
    mkdir -p "$TARGET_DIR/static" "$TARGET_DIR/media"
    python manage.py collectstatic --noinput

    # 重启Nginx
    systemctl enable nginx
    systemctl restart nginx
}

# 配置Gunicorn服务
setup_gunicorn() {
    cat > /etc/systemd/system/allenpanel.service << EOF
[Unit]
Description=AllenPanel Django Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/allenpanel
Environment=PATH=/opt/allenpanel/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/allenpanel/venv/bin/gunicorn \\
    --workers 3 \\
    --bind 127.0.0.1:8000 \\
    --access-logfile /var/log/gunicorn-access.log \\
    --error-logfile /var/log/gunicorn-error.log \\
    webpanel.wsgi:application
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # 创建日志文件
    touch /var/log/gunicorn-access.log /var/log/gunicorn-error.log
    chmod 644 /var/log/gunicorn-*.log

    # 启动服务
    systemctl daemon-reload
    systemctl enable allenpanel
    systemctl start allenpanel
}

# 显示菜单
show_menu() {
    echo -e "\n${GREEN}Web面板管理脚本${NC}"
    echo "------------------------"
    echo "1. 安装Web面板"
    echo "2. 卸载Web面板"
    echo "3. 修改管理员密码"
    echo "4. 重启面板服务"
    echo "0. 退出"
    echo "------------------------"
}

# 主程序
main() {
    check_os
    while true; do
        show_menu
        read -p "请输入选项 [0-4]: " choice
        case $choice in
            1)
                # 确保先安装依赖
                install_dependencies
                if [ $? -eq 0 ]; then
                    install_panel
                else
                    echo -e "${RED}依赖安装失败，请检查系统环境${NC}"
                fi
                ;;
            2)
                uninstall_panel
                ;;
            3)
                change_admin_password
                ;;
            4)
                restart_panel
                ;;
            0)
                echo "退出程序"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选项${NC}"
                ;;
        esac
    done
}

# 运行主程序
main 