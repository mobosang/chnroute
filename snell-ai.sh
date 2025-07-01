#!/bin/bash

# ==============================================================================
# Snell Server 全功能管理脚本 (定制版-GOOGLE AI 生成)
#
# v3.1.0:
# - 新增：跨发行版兼容性适配 (CentOS, RHEL, Ubuntu, Debian)。
# - 新增：自动检测并配置防火墙 (firewalld, ufw)。
# - 新增：SELinux 状态检测与警告 (针对 CentOS/RHEL)。
# - 优化：兼容旧版 systemd (如 CentOS 7)，自动切换服务用户模式。
# - 优化：依赖安装列表增加 openssl。
#
# v3.0.0: 新增版本更换功能
#
# 特性:
# - TUI 菜单式管理界面
# - 采用用户指定的 Snell 和 Shadow-TLS 原始配置
# - 支持安装、卸载、启动、停止、重启服务
# - 新增: 一键更新/更换 Snell Server 版本
# - 可选安装模式 (Snell-only 或 Snell + Shadow-TLS)
# - 自动检测运行状态
# - 持久化配置，方便管理
# - 一键更新脚本
# ==============================================================================

# --- 全局变量和常量 ---
SCRIPT_VERSION="3.1.0"
SNELL_VERSION_FOR_INSTALL="v4.1.1" # 用于全新安装时的默认版本
SHADOW_TLS_VERSION="v0.2.25"

# --- 文件路径 ---
SNELL_INSTALL_DIR="/usr/local/bin"
SNELL_CONFIG_DIR="/etc/snell"
SNELL_CONFIG_FILE="${SNELL_CONFIG_DIR}/snell-server.conf"
SNELL_SERVICE_FILE="/etc/systemd/system/snell.service"
SHADOW_TLS_SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
SCRIPT_CONFIG_FILE="${SNELL_CONFIG_DIR}/manager.conf"

# --- 下载链接 ---
SNELL_RELEASE_NOTES_URL="https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell"
SHADOW_TLS_URL="https://github.com/ihciah/shadow-tls/releases/download/${SHADOW_TLS_VERSION}/shadow-tls-x86_64-unknown-linux-musl"
SCRIPT_URL="https://raw.githubusercontent.com/mobosang/chnroute/main/snell-ai.sh"

# --- 颜色定义 ---
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
NC="\033[0m"

# --- 状态变量 ---
is_installed=false
is_running=false
install_mode=""
snell_version_installed=""

# --- 工具函数 ---
press_any_key() {
    echo -e "\n${Yellow}按任意键返回主菜单...${NC}"
    read -r -n 1 -s
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${Red}错误：此脚本必须以 root 权限运行。${NC}"
        exit 1
    fi
}

## MODIFICATION ## - 增强的依赖安装
install_dependencies() {
    # 检查 dialog 是否已安装，作为判断是否需要安装依赖的标志
    if command -v dialog &> /dev/null; then
        return
    fi
    
    echo "正在安装必要的依赖 (dialog, curl, wget, unzip, openssl)..."
    
    # Debian/Ubuntu
    if command -v apt-get &> /dev/null; then
        apt-get update >/dev/null 2>&1
        apt-get install -y dialog curl wget unzip openssl >/dev/null 2>&1
    # CentOS/RHEL (Yum)
    elif command -v yum &> /dev/null; then
        yum install -y epel-release >/dev/null 2>&1 # dialog 在 epel 源中
        yum install -y dialog curl wget unzip openssl >/dev/null 2>&1
    # Fedora/RHEL (DNF)
    elif command -v dnf &> /dev/null; then
        dnf install -y epel-release >/dev/null 2>&1
        dnf install -y dialog curl wget unzip openssl >/dev/null 2>&1
    else
        echo -e "${Red}无法确定包管理器，请手动安装: dialog, curl, wget, unzip, openssl${NC}"
        exit 1
    fi
}

## MODIFICATION ## - 新增防火墙配置函数
open_firewall_ports() {
    local port=$1
    echo "正在配置防火墙以开放端口: ${port}/tcp and ${port}/udp"

    # firewalld (CentOS/RHEL)
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="${port}/tcp" --permanent >/dev/null 2>&1
        firewall-cmd --zone=public --add-port="${port}/udp" --permanent >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "${Green}firewalld 规则已添加。${NC}"
    # ufw (Ubuntu/Debian)
    elif command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${port}" >/dev/null 2>&1
        ufw reload >/dev/null 2>&1
        echo -e "${Green}ufw 规则已添加。${NC}"
    else
        echo -e "${Yellow}未检测到活动的 firewalld 或 ufw。请手动开放端口: ${port}${NC}"
    fi
}

## MODIFICATION ## - 新增SELinux检测函数
check_selinux() {
    # 仅在 RHEL/CentOS 系列系统上检查
    if [[ -f /etc/redhat-release ]] && command -v sestatus &> /dev/null; then
        sestatus_output=$(sestatus)
        if echo "$sestatus_output" | grep -q "SELinux status:.*enabled" && echo "$sestatus_output" | grep -q "Current mode:.*enforcing"; then
            echo -e "\n${Yellow}==================== SELinux 警告 ====================${NC}"
            echo -e "${Yellow}检测到您的系统正在运行于 SELinux Enforcing 模式。${NC}"
            echo -e "${Yellow}这可能会阻止 Snell 正常运行。如果遇到问题，请尝试：${NC}"
            echo -e "${Yellow}1. 临时设置为宽容模式: ${NC}${Green}sudo setenforce 0${NC}"
            echo -e "${Yellow}2. 永久设置为宽容模式: 修改 ${NC}${Green}/etc/selinux/config${NC}${Yellow} 文件中的 ${NC}${Green}SELINUX=permissive${NC}"
            echo -e "${Yellow}======================================================${NC}"
            press_any_key
        fi
    fi
}

load_config() {
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        source "$SCRIPT_CONFIG_FILE"
        snell_version_installed=$SNELL_VERSION_INSTALLED
    fi
}

check_status() {
    load_config
    if [[ -f "$SNELL_INSTALL_DIR/snell-server" && -f "$SNELL_CONFIG_FILE" ]]; then
        is_installed=true
        if [[ -z "$snell_version_installed" ]]; then
            snell_version_installed="$SNELL_VERSION_FOR_INSTALL"
        fi
    else
        is_installed=false
        is_running=false
        snell_version_installed=""
        return
    fi

    if systemctl is-active --quiet snell.service; then
        if [[ "$INSTALL_MODE" == "full" ]]; then
            if systemctl is-active --quiet shadow-tls.service; then
                is_running=true
            else
                is_running=false
            fi
        else
            is_running=true
        fi
    else
        is_running=false
    fi
}

# --- 核心功能函数 ---

## 修改 ## - 获取 Snell 最新版本号
get_latest_snell_version() {
    local version
    version=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[^-]+' | sort -uV | tail -n 1)
    if [[ -z "$version" ]]; then
        echo "error"
    else
        echo "$version"
    fi
}

## 新增函数 ## - 获取所有可用的 Snell 版本列表 (从新到旧排序)
get_available_versions() {
    local versions
    versions=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[^-]+' | sort -urV)
    if [[ -z "$versions" ]]; then
        echo "error"
    else
        echo "$versions"
    fi
}

do_install() {
    local title="安装 Snell Server"
    if $is_installed; then
        title="修改配置"
        dialog --title "$title" --yesno "您已安装 Snell。要重新配置吗？\n\n这将覆盖现有设置并重启服务。" 10 50
        if [[ $? -ne 0 ]]; then return; fi
    else
        ## MODIFICATION ## - 首次安装时检查 SELinux
        check_selinux
    fi

    local choice
    choice=$(dialog --clear --backtitle "Snell 安装向导" --title "模式选择" \
        --radiolist "请选择安装模式 (按空格键选择):" 15 60 2 \
        "full" "Snell + Shadow-TLS (推荐)" "on" \
        "snell_only" "仅 Snell (轻量)" "off" \
        3>&1 1>&2 2>&3)
    
    if [[ -z "$choice" ]]; then echo "取消安装。"; return; fi
    
    local agent_name="MyNode"
    local snell_port="36139"
    local public_port="56139"
    local shadow_tls_sni=""

    local form_items
    if [[ "$choice" == "full" ]]; then
        shadow_tls_sni="quark.cn"
        form_items=(
            "节点名称:" 1 1 "$agent_name" 1 28 40 0
            "Shadow-TLS 端口 (对外):" 2 1 "$public_port" 2 28 40 0
            "Snell 内部端口:" 3 1 "$snell_port" 3 28 40 0
            "Shadow-TLS 伪装域名:" 4 1 "$shadow_tls_sni" 4 28 40 0
        )
    else
        form_items=(
            "节点名称:" 1 1 "$agent_name" 1 28 40 0
            "Snell 端口 (对外):" 2 1 "$snell_port" 2 28 40 0
        )
    fi

    local form_output
    form_output=$(dialog --clear --backtitle "Snell 安装向导" --title "参数配置" --form "请输入以下参数:" 15 75 4 "${form_items[@]}" 3>&1 1>&2 2>&3)

    if [[ -z "$form_output" ]]; then echo "取消安装。"; return; fi

    AGENT_NAME=$(echo "$form_output" | sed -n '1p')
    if [[ "$choice" == "full" ]]; then
        INSTALL_MODE="full"; PUBLIC_PORT=$(echo "$form_output" | sed -n '2p'); SNELL_PORT=$(echo "$form_output" | sed -n '3p'); SHADOW_TLS_SNI=$(echo "$form_output" | sed -n '4p'); SNELL_LISTEN_ADDR="127.0.0.1"
    else
        INSTALL_MODE="snell_only"; SNELL_PORT=$(echo "$form_output" | sed -n '2p'); PUBLIC_PORT=$SNELL_PORT; SNELL_LISTEN_ADDR="0.0.0.0"
    fi

    clear
    echo "开始准备安装环境..."
    if $is_installed; then systemctl stop snell.service shadow-tls.service >/dev/null 2>&1; fi
    mkdir -p "$SNELL_INSTALL_DIR" "$SNELL_CONFIG_DIR"

    echo "正在下载 Snell Server..."
    local temp_zip; temp_zip=$(mktemp)
    local SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION_FOR_INSTALL}-linux-amd64.zip"
    if ! wget -qO "$temp_zip" "$SNELL_URL"; then
        dialog --title "错误" --msgbox "下载 Snell Server 失败！\n\n请检查网络连接或确认下载链接有效。" 10 60; rm -f "$temp_zip"; return 1
    fi
    unzip -qo "$temp_zip" -d "$SNELL_INSTALL_DIR"; rm -f "$temp_zip"

    if [[ ! -f "$SNELL_INSTALL_DIR/snell-server" ]]; then
        dialog --title "错误" --msgbox "Snell Server 安装失败！\n\n无法在 $SNELL_INSTALL_DIR 中找到文件 'snell-server'。" 12 70; return 1
    fi
    chmod +x "$SNELL_INSTALL_DIR/snell-server"; echo -e "${Green}Snell Server 二进制文件准备就绪。${NC}"

    if [[ "$INSTALL_MODE" == "full" ]]; then
        echo "正在下载 Shadow-TLS..."
        if ! wget -qO "$SNELL_INSTALL_DIR/shadow-tls" "$SHADOW_TLS_URL"; then
            dialog --title "错误" --msgbox "下载 Shadow-TLS 失败！\n\n请检查网络连接或确认下载链接有效。" 10 60; return 1
        fi
        chmod +x "$SNELL_INSTALL_DIR/shadow-tls"; echo -e "${Green}Shadow-TLS 二进制文件准备就绪。${NC}"
    fi

    echo "所有二进制文件验证通过，正在写入配置文件..."
    SNELL_PSK=$(openssl rand -base64 18)
    local SHADOW_TLS_PSK=""; if [[ "$INSTALL_MODE" == "full" ]]; then SHADOW_TLS_PSK=$(openssl rand -base64 18); fi
    
    cat > "$SNELL_CONFIG_FILE" << EOF
[snell-server]
dns = 1.1.1.1, 9.9.9.9, 2606:4700:4700::1111
listen = ${SNELL_LISTEN_ADDR}:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = false
EOF

    ## MODIFICATION ## - 兼容旧版 Systemd (CentOS 7)
    local service_user_line="DynamicUser=yes"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "centos" && "$VERSION_ID" == "7" ]]; then
            echo "检测到 CentOS 7，使用静态用户 'snell' 运行服务。"
            # 创建一个无密码、无主目录、无shell的系统用户
            if ! id "snell" &>/dev/null; then
                useradd -r -s /bin/false snell
            fi
            service_user_line="User=snell"
        fi
    fi

    cat > "$SNELL_SERVICE_FILE" << EOF
[Unit]
Description=Snell Proxy Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
Type=simple
${service_user_line}
LimitNOFILE=32768
ExecStart=${SNELL_INSTALL_DIR}/snell-server -c ${SNELL_CONFIG_FILE}
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

    if [[ "$INSTALL_MODE" == "full" ]]; then
        cat > "$SHADOW_TLS_SERVICE_FILE" << EOF
[Unit]
Description=Shadow-TLS Server Service
Documentation=man:sstls-server
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=MONOIO_FORCE_LEGACY_DRIVER=1
ExecStart=${SNELL_INSTALL_DIR}/shadow-tls --fastopen --v3 server --listen ::0:${PUBLIC_PORT} --server 127.0.0.1:${SNELL_PORT} --tls ${SHADOW_TLS_SNI} --password ${SHADOW_TLS_PSK}
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=shadow-tls
[Install]
WantedBy=multi-user.target
EOF
    else
        rm -f "$SHADOW_TLS_SERVICE_FILE"
    fi
    
    cat > "$SCRIPT_CONFIG_FILE" << EOF
AGENT_NAME="${AGENT_NAME}"
INSTALL_MODE="${INSTALL_MODE}"
SNELL_PORT="${SNELL_PORT}"
PUBLIC_PORT="${PUBLIC_PORT}"
SNELL_PSK="${SNELL_PSK}"
SNELL_VERSION_INSTALLED="${SNELL_VERSION_FOR_INSTALL}"
EOF
    if [[ "$INSTALL_MODE" == "full" ]]; then
        cat >> "$SCRIPT_CONFIG_FILE" << EOF
SHADOW_TLS_SNI="${SHADOW_TLS_SNI}"
SHADOW_TLS_PSK="${SHADOW_TLS_PSK}"
EOF
    fi

    sed -i -e '/# Kernel network tuning by Snell manager script/,+4d' /etc/sysctl.conf
    cat <<EOF >> /etc/sysctl.conf

# Kernel network tuning by Snell manager script
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_ecn = 1
EOF
    sysctl -p >/dev/null

    systemctl daemon-reload
    systemctl enable snell.service >/dev/null 2>&1
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl enable shadow-tls.service >/dev/null 2>&1; else systemctl disable shadow-tls.service >/dev/null 2>&1; fi
    
    ## MODIFICATION ## - 安装后自动配置防火墙
    open_firewall_ports "$PUBLIC_PORT"

    check_status
    do_restart
    
    clear
    echo -e "${Green}安装/配置成功完成！${NC}"
    view_config
}

## 更新 Snell Server 版本
do_update_snell() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装，无法更新。" 8 40
        return
    fi
    clear
    echo -e "${Yellow}正在检查最新版本...${NC}"
    local remote_version
    remote_version=$(get_latest_snell_version)
    if [[ "$remote_version" == "error" || -z "$remote_version" ]]; then
        dialog --title "错误" --msgbox "获取远程版本信息失败！\n\n请检查网络或稍后再试。" 10 50
        return
    fi

    echo -e "当前已安装版本: ${Green}${snell_version_installed}${NC}"
    echo -e "远程最新版本:   ${Green}${remote_version}${NC}"
    if [[ "$snell_version_installed" == "$remote_version" ]]; then
        dialog --title "提示" --msgbox "恭喜！您的 Snell Server 已是最新版本。" 8 50
        return
    fi

    dialog --title "发现新版本" --yesno "发现新版本 ${remote_version}。\n\n是否要从 ${snell_version_installed} 更新？" 10 50
    if [[ $? -ne 0 ]]; then
        echo "用户取消更新。"
        return
    fi

    clear
    echo "正在准备更新..."
    echo "停止相关服务..."
    systemctl stop snell.service shadow-tls.service >/dev/null 2>&1

    echo "正在下载新版本 Snell Server (${remote_version})..."
    local temp_zip; temp_zip=$(mktemp)
    local NEW_SNELL_URL="https://dl.nssurge.com/snell/snell-server-${remote_version}-linux-amd64.zip"
    if ! wget -qO "$temp_zip" "$NEW_SNELL_URL"; then
        echo -e "${Red}下载新版本失败！请检查网络。${NC}"
        echo "正在回滚，重启旧版本服务..."
        systemctl start snell.service
        if [[ "$INSTALL_MODE" == "full" ]]; then systemctl start shadow-tls.service; fi
        rm -f "$temp_zip"
        press_any_key
        return
    fi

    echo "下载完成，正在替换文件..."
    unzip -qo "$temp_zip" -d "$SNELL_INSTALL_DIR"
    rm -f "$temp_zip"
    if [[ ! -f "$SNELL_INSTALL_DIR/snell-server" ]]; then
        echo -e "${Red}更新失败！解压后未找到 snell-server 文件。${NC}"
        press_any_key
        return
    fi

    chmod +x "$SNELL_INSTALL_DIR/snell-server"
    echo "更新配置文件中的版本记录..."
    sed -i "s/^SNELL_VERSION_INSTALLED=.*/SNELL_VERSION_INSTALLED=\"${remote_version}\"/" "$SCRIPT_CONFIG_FILE"
    
    echo "正在重启服务以应用更新..."
    do_restart
    
    check_status
    echo -e "${Green}Snell Server 已成功更新至 ${remote_version}！${NC}"
    press_any_key
}

## 新增函数 ## - 更换 Snell Server 版本
do_rollback_snell() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装，无法更换。" 8 40
        return
    fi

    clear
    echo -e "${Yellow}正在获取可用版本列表...${NC}"
    local available_versions
    available_versions=$(get_available_versions)

    if [[ "$available_versions" == "error" || -z "$available_versions" ]]; then
        dialog --title "错误" --msgbox "获取版本列表失败！\n\n请检查网络或稍后再试。" 10 50
        return
    fi

    # 过滤掉当前已安装的版本
    local current_version=$snell_version_installed
    local rollback_options
    rollback_options=$(echo "$available_versions" | grep -v "^${current_version}$")

    if [[ -z "$rollback_options" ]]; then
        dialog --title "提示" --msgbox "没有找到比当前版本 (${current_version}) 更早的可更换版本。" 8 60
        return
    fi

    # 创建 dialog 菜单项
    local menu_items=()
    local count=1
    while IFS= read -r version; do
        menu_items+=("$count" "$version")
        ((count++))
    done <<< "$rollback_options"
    
    local choice
    choice=$(dialog --clear --backtitle "版本更换" --title "选择要更换到的版本" \
        --menu "当前版本为 ${current_version}。\n请选择一个目标版本进行更换 (从新到旧排序):" 20 60 15 \
        "${menu_items[@]}" \
        3>&1 1>&2 2>&3)

    if [[ $? -ne 0 ]]; then
        echo "用户取消更换。"
        return
    fi

    local selected_version
    selected_version=$(echo "$rollback_options" | sed -n "${choice}p")

    if [[ -z "$selected_version" ]]; then
        echo "无效选择。"
        return
    fi
    
    dialog --title "确认更换" --yesno "确定要将版本从 ${current_version} 更换到 ${selected_version} 吗？" 10 50
    if [[ $? -ne 0 ]]; then
        echo "用户取消更换。"
        return
    fi

    clear
    echo "正在准备更换至 ${selected_version}..."
    echo "停止相关服务..."
    systemctl stop snell.service shadow-tls.service >/dev/null 2>&1
    
    echo "正在下载版本 ${selected_version}..."
    local temp_zip; temp_zip=$(mktemp)
    local ROLLBACK_URL="https://dl.nssurge.com/snell/snell-server-${selected_version}-linux-amd64.zip"
    
    if ! wget -qO "$temp_zip" "$ROLLBACK_URL"; then
        echo -e "${Red}下载旧版本失败！请检查网络。${NC}"
        echo "正在回滚，重启之前的服务..."
        systemctl start snell.service
        if [[ "$INSTALL_MODE" == "full" ]]; then systemctl start shadow-tls.service; fi
        rm -f "$temp_zip"
        press_any_key
        return
    fi
    
    echo "下载完成，正在替换文件..."
    unzip -qo "$temp_zip" -d "$SNELL_INSTALL_DIR"
    rm -f "$temp_zip"
    
    if [[ ! -f "$SNELL_INSTALL_DIR/snell-server" ]]; then
        echo -e "${Red}更换失败！解压后未找到 snell-server 文件。${NC}"
        press_any_key
        return
    fi
    chmod +x "$SNELL_INSTALL_DIR/snell-server"
    
    echo "更新配置文件中的版本记录..."
    sed -i "s/^SNELL_VERSION_INSTALLED=.*/SNELL_VERSION_INSTALLED=\"${selected_version}\"/" "$SCRIPT_CONFIG_FILE"
    
    echo "正在重启服务以应用新版本..."
    do_restart
    
    check_status
    echo -e "${Green}Snell Server 已成功更换至 ${selected_version}！${NC}"
    press_any_key
}

do_uninstall() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    dialog --title "确认卸载" --yesno "确定要卸载 Snell Server 吗？\n\n这将删除所有相关文件和配置！" 10 50
    if [[ $? -ne 0 ]]; then return; fi
    clear
    echo "正在卸载..."
    systemctl stop snell.service shadow-tls.service >/dev/null 2>&1
    systemctl disable snell.service shadow-tls.service >/dev/null 2>&1
    rm -f "$SNELL_INSTALL_DIR/snell-server" "$SNELL_INSTALL_DIR/shadow-tls"
    rm -rf "$SNELL_CONFIG_DIR"
    rm -f "$SNELL_SERVICE_FILE" "$SHADOW_TLS_SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${Green}卸载完成！${NC}"
    press_any_key
}

do_start() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    if $is_running; then
        dialog --title "提示" --msgbox "Snell 已在运行中。" 8 40
        return
    fi
    echo "正在启动服务..."
    systemctl start snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl start shadow-tls.service; fi
    sleep 1
    check_status
    if $is_running; then
        echo -e "${Green}启动成功！${NC}"
    else
        echo -e "${Red}启动失败。${NC}"
    fi
    press_any_key
}

do_stop() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    if ! $is_running; then
        dialog --title "提示" --msgbox "Snell 未运行。" 8 40
        return
    fi
    echo "正在停止服务..."
    systemctl stop snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl stop shadow-tls.service; fi
    sleep 1
    echo -e "${Green}服务已停止。${NC}"
    press_any_key
}

do_restart() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    echo "正在重启服务..."
    systemctl restart snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl restart shadow-tls.service; fi
    sleep 1
    check_status
    if $is_running; then
        echo -e "${Green}重启成功！${NC}"
    else
        echo -e "${Red}重启失败。${NC}"
    fi
}

view_config() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    load_config
    
    local temp_version=${snell_version_installed#v}
    local snell_major_version=${temp_version:0:1}

    local public_ip
    public_ip=$(curl -s4 ifconfig.me)
    local final_config_string
    if [[ "$INSTALL_MODE" == "full" ]]; then
        final_config_string="${AGENT_NAME} = snell, ${public_ip}, ${PUBLIC_PORT}, psk=${SNELL_PSK}, version=${snell_major_version}, reuse=true, tfo=true, ecn=true, shadow-tls-password=${SHADOW_TLS_PSK}, shadow-tls-sni=${SHADOW_TLS_SNI}, shadow-tls-version=3"
    else
        final_config_string="${AGENT_NAME} = snell, ${public_ip}, ${PUBLIC_PORT}, psk=${SNELL_PSK}, version=${snell_major_version}, reuse=true, tfo=true, ecn=true"
    fi
    
    local preview_message="配置已生成。\n\n关闭此窗口后，客户端配置将打印在终端中，以便于复制。"
    dialog --title "客户端配置信息" --msgbox "${preview_message}" 10 60
    
    clear
    echo -e "${Green}==================================================================${NC}"
    echo -e "${Yellow}请复制以下完整的客户端配置信息：${NC}\n"
    echo "${final_config_string}"
    echo -e "\n${Green}==================================================================${NC}"
    press_any_key
}

view_log() {
    if ! $is_installed; then 
        dialog --title "提示" --msgbox "Snell 未安装，无法查看日志。" 8 40
        return
    fi
    if [[ "$INSTALL_MODE" == "full" ]]; then
        local log_choice
        log_choice=$(dialog --clear --backtitle "日志查看" --title "选择要查看的日志" \
            --menu "当前为 Snell + Shadow-TLS 模式，请选择：" 15 60 3 \
            "1" "查看 Snell 服务日志 (snell-server)" \
            "2" "查看 Shadow-TLS 服务日志 (shadow-tls)" \
            "3" "查看合并日志 (用于排查交互问题)" \
            3>&1 1>&2 2>&3)
        if [[ -z "$log_choice" ]]; then return; fi
        local service_to_log=""
        case "$log_choice" in
            1) service_to_log="-u snell.service" ;;
            2) service_to_log="-u shadow-tls.service" ;;
            3) service_to_log="-u snell.service -u shadow-tls.service" ;;
            *) return ;;
        esac
        clear
        echo -e "正在加载日志... ${Yellow}(使用箭头滚动，按 'q' 键退出返回菜单)${NC}"; sleep 1
        # shellcheck disable=SC2086
        journalctl -e $service_to_log
    else
        clear
        echo -e "正在加载 Snell 日志... ${Yellow}(使用箭头滚动，按 'q' 键退出返回菜单)${NC}"; sleep 1
        journalctl -e -u snell.service
    fi
}

update_script() {
    clear
    echo "正在检查更新..."
    
    local local_version=$SCRIPT_VERSION
    local remote_version
    remote_version=$(curl -sL "${SCRIPT_URL}" | grep 'SCRIPT_VERSION=' | head -n 1 | awk -F'"' '{print $2}')

    if [[ -z "$remote_version" ]]; then
        echo -e "${Red}获取远程版本信息失败，请检查网络或脚本URL。${NC}"
        press_any_key
        return
    fi

    # 使用 sort -V 进行版本号比较
    local latest_version
    latest_version=$(printf "%s\n%s" "$local_version" "$remote_version" | sort -V | tail -n 1)

    if [[ "$latest_version" == "$local_version" ]]; then
        echo -e "${Green}恭喜！当前已是最新版本 (${local_version})。${NC}"
    else
        echo -e "${Yellow}发现新版本: ${remote_version}，正在更新...${NC}"
        local script_path="$0"
        if ! curl -sL "${SCRIPT_URL}" -o "${script_path}"; then
            echo -e "${Red}下载新脚本失败！${NC}"
            press_any_key
            return
        fi
        chmod +x "${script_path}"
        echo -e "${Green}脚本已更新至 ${remote_version}！正在重新运行...${NC}"
        sleep 2
        exec "${script_path}"
    fi
    press_any_key
}

## MODIFICATION ## - 更新主菜单显示，统一菜单项
show_menu() {
    check_status
    clear
    local mode_display_text=""
    if $is_installed; then
        if [[ "$INSTALL_MODE" == "full" ]]; then
            mode_display_text=" (Snell + Shadow-TLS)"
        elif [[ "$INSTALL_MODE" == "snell_only" ]]; then
            mode_display_text=" (仅 Snell)"
        fi
    fi

    local status_text
    if $is_installed; then
        status_text="已安装 [${snell_version_installed}]${mode_display_text}"
        if $is_running; then
            status_text="${Green}${status_text} 并已启动${NC}"
        else
            status_text="${Red}${status_text} 但未启动${NC}"
        fi
    else
        status_text="${Red}未安装${NC}"
    fi

    echo -e "Snell Server 管理脚本 [v${SCRIPT_VERSION}]"
    echo -e "================================================="
    echo -e "${Green}0.${NC} 更新脚本"
    echo -e "-------------------------------------------------"
    echo -e "${Green}1.${NC} 安装 Snell Server"
    echo -e "${Yellow}2.${NC} 更新 Snell 版本"
    echo -e "${Yellow}3.${NC} 更换 Snell 版本"
    echo -e "${Green}4.${NC} 卸载 Snell Server"
    echo -e "-------------------------------------------------"
    echo -e "${Green}5.${NC} 启动 Snell Server"
    echo -e "${Green}6.${NC} 停止 Snell Server"
    echo -e "${Green}7.${NC} 重启 Snell Server"
    echo -e "-------------------------------------------------"
    echo -e "${Green}8.${NC} 修改配置信息  (同安装)"
    echo -e "${Green}9.${NC} 查看配置信息"
    echo -e "${Green}10.${NC} 查看运行状态  (日志)"
    echo -e "-------------------------------------------------"
    echo -e "${Green}11.${NC} 退出脚本"
    echo -e "================================================="
    echo -e "当前状态：${status_text}\n"
}

## MODIFICATION ## - 更新主循环逻辑
main() {
    check_root
    install_dependencies
    while true; do
        show_menu
        read -p "请输入数字 [0-11]: " choice
        case "$choice" in
            0) update_script ;; 
            1) do_install ;; 
            2) do_update_snell ;;
            3) do_rollback_snell ;;
            4) do_uninstall ;;
            5) do_start ;;
            6) do_stop ;;
            7) do_restart; press_any_key ;;
            8) do_install ;;
            9) view_config ;;
            10) view_log ;;
            11) exit 0 ;;
            *) echo -e "${Red}无效输入。${NC}"; sleep 1 ;;
        esac
    done
}

main
