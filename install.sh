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
            # 添加 Caddy 官方源
            sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
            sudo apt-get update
            sudo apt-get install -y wget vim unzip tar git python3-venv python3-pip caddy
            ;;
        "centos")
            if [ "$VERSION_ID" = "8" ] || [ "$VERSION_ID" = "9" ]; then
                # 添加 Caddy 的 COPR 源
                sudo dnf install -y 'dnf-command(copr)'
                sudo dnf copr enable -y @caddy/caddy
                sudo dnf -y install wget vim unzip tar git python3-devel caddy
            else
                sudo yum -y install epel-release
                sudo yum -y install wget vim unzip tar git python3-devel
                # 为 CentOS 7 安装 Caddy
                sudo yum install -y yum-plugin-copr
                sudo yum copr enable -y @caddy/caddy
                sudo yum install -y caddy
            fi
            ;;
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            exit 1
            ;;
    esac

    # 验证必要组件是否安装成功
    for cmd in wget vim unzip tar git caddy; do
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

    # 配置Caddy（替代原来的setup_nginx）
    setup_caddy

    # 配置Gunicorn服务
    setup_gunicorn

    # 清理临时文件
    cd
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}安装完成！${NC}"
    echo -e "${GREEN}http:ip:8888,admin,admin${NC}"
}

# 卸载面板
uninstall_panel() {
    echo -e "${RED}开始卸载Web面板...${NC}"
    
    # 停止服务
    systemctl stop allenpanel
    systemctl disable allenpanel
    systemctl stop caddy
    systemctl disable caddy
    
    # 删除服务文件
    case $OS in
        "ubuntu"|"debian")
            sudo apt-get remove -y caddy
            ;;
        "centos")
            sudo dnf remove -y caddy || sudo yum remove -y caddy
            ;;
    esac
    
    rm -f /etc/systemd/system/allenpanel.service
    rm -f /etc/caddy/Caddyfile
    
    # 删除安装目录
    rm -rf "$TARGET_DIR"
    
    # 重载服务
    systemctl daemon-reload
    
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
    systemctl restart caddy
    echo -e "${GREEN}服务已重启${NC}"
}

# 配置Caddy（替代原来的setup_nginx函数）
setup_caddy() {
    # 创建 Caddy 配置文件
    cat > /etc/caddy/Caddyfile << EOF
:8888 {
    root * /opt/allenpanel/static
    file_server

    handle /static/* {
        root * /opt/allenpanel
        file_server
    }

    handle /media/* {
        root * /opt/allenpanel
        file_server
    }

    handle /* {
        reverse_proxy 127.0.0.1:8000
    }

    log {
        output file /var/log/caddy/access.log
    }
}
EOF

    # 创建日志目录
    sudo mkdir -p /var/log/caddy
    sudo chown caddy:caddy /var/log/caddy

    # 创建静态文件目录
    mkdir -p "$TARGET_DIR/static" "$TARGET_DIR/media"
    python manage.py collectstatic --noinput

    # 启动 Caddy 服务
    systemctl enable caddy
    systemctl restart caddy
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