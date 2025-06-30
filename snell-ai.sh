#!/bin/bash

# ==============================================================================
# Snell Server 全功能管理脚本 (定制版)
#
# v2.3.0: 优化了日志查看功能，按 'q' 即可退出返回主菜单。
#
# 特性:
# - TUI 菜单式管理界面
# - 采用用户指定的 Snell 和 Shadow-TLS 原始配置
# - 支持安装、卸载、启动、停止、重启服务
# - 可选安装模式 (Snell-only 或 Snell + Shadow-TLS)
# - 自动检测运行状态
# - 持久化配置，方便管理
# - 一键更新脚本
# ==============================================================================

# --- 全局变量和常量 ---
SCRIPT_VERSION="2.3.0-custom"
SNELL_VERSION="v5.0.0b1"
SHADOW_TLS_VERSION="v0.2.25"

# --- 文件路径 ---
SNELL_INSTALL_DIR="/usr/local/bin"
SNELL_CONFIG_DIR="/etc/snell"
SNELL_CONFIG_FILE="${SNELL_CONFIG_DIR}/snell-server.conf"
SNELL_SERVICE_FILE="/etc/systemd/system/snell.service"
SHADOW_TLS_SERVICE_FILE="/etc/systemd/system/shadow-tls.service"
SCRIPT_CONFIG_FILE="${SNELL_CONFIG_DIR}/manager.conf"

# --- 下载链接 ---
SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-amd64.zip"
SHADOW_TLS_URL="https://github.com/ihciah/shadow-tls/releases/download/${SHADOW_TLS_VERSION}/shadow-tls-x86_64-unknown-linux-musl"
SCRIPT_URL="https://raw.githubusercontent.com/user/repo/branch/snell_manager.sh"

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

install_dependencies() {
    if ! command -v dialog &> /dev/null; then
        echo "正在安装必要的依赖 (dialog, curl, wget, unzip)..."
        apt-get update >/dev/null 2>&1
        apt-get install -y dialog curl wget unzip >/dev/null 2>&1
    fi
}

load_config() {
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        source "$SCRIPT_CONFIG_FILE"
    fi
}

check_status() {
    load_config
    if [[ -f "$SNELL_INSTALL_DIR/snell-server" && -f "$SNELL_CONFIG_FILE" ]]; then
        is_installed=true
        snell_version_installed=$($SNELL_INSTALL_DIR/snell-server -v 2>/dev/null | awk '{print $3}')
        [[ -z "$snell_version_installed" ]] && snell_version_installed="v4+"
    else
        is_installed=false
        is_running=false
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
do_install() {
    local title="安装 Snell Server"
    if $is_installed; then
        title="修改配置"
        dialog --title "$title" --yesno "您已安装 Snell。要重新配置吗？\n\n这将覆盖现有设置并重启服务。" 10 50
        if [[ $? -ne 0 ]]; then return; fi
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
    local shadow_tls_sni="quark.cn"

    local form_items
    if [[ "$choice" == "full" ]]; then
        form_items=(
            "节点名称:" 1 1 "$agent_name" 1 20 40 0
            "Shadow-TLS 端口 (对外):" 2 1 "$public_port" 2 20 40 0
            "Snell 内部端口:" 3 1 "$snell_port" 3 20 40 0
            "Shadow-TLS 伪装域名:" 4 1 "$shadow_tls_sni" 4 20 40 0
        )
    else
        form_items=(
            "节点名称:" 1 1 "$agent_name" 1 20 40 0
            "Snell 端口 (对外):" 2 1 "$snell_port" 2 20 40 0
        )
    fi

    local form_output
    form_output=$(dialog --clear --backtitle "Snell 安装向导" --title "参数配置" \
        --form "请输入以下参数:" 15 60 4 "${form_items[@]}" 3>&1 1>&2 2>&3)

    if [[ -z "$form_output" ]]; then echo "取消安装。"; return; fi

    AGENT_NAME=$(echo "$form_output" | sed -n '1p')
    if [[ "$choice" == "full" ]]; then
        INSTALL_MODE="full"
        PUBLIC_PORT=$(echo "$form_output" | sed -n '2p')
        SNELL_PORT=$(echo "$form_output" | sed -n '3p')
        SHADOW_TLS_SNI=$(echo "$form_output" | sed -n '4p')
        SNELL_LISTEN_ADDR="127.0.0.1"
    else
        INSTALL_MODE="snell_only"
        SNELL_PORT=$(echo "$form_output" | sed -n '2p')
        PUBLIC_PORT=$SNELL_PORT
        SNELL_LISTEN_ADDR="0.0.0.0"
    fi

    echo "开始安装..."
    if $is_installed; then
        systemctl stop snell.service shadow-tls.service >/dev/null 2>&1
    fi

    mkdir -p "$SNELL_INSTALL_DIR"
    wget -qO snell.zip "$SNELL_URL" && unzip -qo snell.zip -d "$SNELL_INSTALL_DIR" && rm snell.zip
    chmod +x "$SNELL_INSTALL_DIR/snell-server"
    if [[ "$INSTALL_MODE" == "full" ]]; then
        wget -qO "$SNELL_INSTALL_DIR/shadow-tls" "$SHADOW_TLS_URL"
        chmod +x "$SNELL_INSTALL_DIR/shadow-tls"
    fi

    SNELL_PSK=$(openssl rand -base64 18)
    if [[ "$INSTALL_MODE" == "full" ]]; then
        SHADOW_TLS_PSK=$(openssl rand -base64 18)
    fi

    mkdir -p "$SNELL_CONFIG_DIR"
    
    cat > "$SNELL_CONFIG_FILE" << EOF
[snell-server]
dns = 1.1.1.1, 9.9.9.9, 2606:4700:4700::1111
listen = ${SNELL_LISTEN_ADDR}:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = false
EOF

    cat > "$SNELL_SERVICE_FILE" << EOF
[Unit]
Description=Snell Proxy Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
Type=simple
DynamicUser=yes
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
SHADOW_TLS_SNI="${SHADOW_TLS_SNI}"
SHADOW_TLS_PSK="${SHADOW_TLS_PSK}"
EOF

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
    if [[ "$INSTALL_MODE" == "full" ]]; then
        systemctl enable shadow-tls.service >/dev/null 2>&1
    else
        systemctl disable shadow-tls.service >/dev/null 2>&1
    fi
    
    do_restart
    
    clear
    echo -e "${Green}安装/配置完成！${NC}"
    view_config
}

do_uninstall() {
    if ! $is_installed; then
        dialog --title "提示" --msgbox "Snell 未安装，无需卸载。" 8 40
        return
    fi
    dialog --title "确认卸载" --yesno "确定要卸载 Snell Server 吗？\n\n这将删除所有相关文件和配置！" 10 50
    if [[ $? -ne 0 ]]; then return; fi
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
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    if $is_running; then dialog --title "提示" --msgbox "Snell 已在运行中。" 8 40; return; fi
    echo "正在启动服务..."
    systemctl start snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then
        systemctl start shadow-tls.service
    fi
    sleep 1
    check_status
    if $is_running; then echo -e "${Green}启动成功！${NC}"; else echo -e "${Red}启动失败，请检查日志。${NC}"; fi
    press_any_key
}

do_stop() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    if ! $is_running; then dialog --title "提示" --msgbox "Snell 未运行。" 8 40; return; fi
    echo "正在停止服务..."
    systemctl stop snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then
        systemctl stop shadow-tls.service
    fi
    sleep 1
    echo -e "${Green}服务已停止。${NC}"
    press_any_key
}

do_restart() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    echo "正在重启服务..."
    systemctl restart snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then
        systemctl restart shadow-tls.service
    fi
    sleep 1
    check_status
    if $is_running; then echo -e "${Green}重启成功！${NC}"; else echo -e "${Red}重启失败，请检查日志。${NC}"; fi
}

view_config() {
    if ! $is_installed; then 
        dialog --title "提示" --msgbox "Snell 未安装，无法查看配置。" 8 40
        return
    fi
    load_config
    local public_ip
    public_ip=$(curl -s4 ifconfig.me)
    local final_config_string
    if [[ "$INSTALL_MODE" == "full" ]]; then
        final_config_string="${AGENT_NAME} = snell, ${public_ip}, ${PUBLIC_PORT}, psk=${SNELL_PSK}, version=5, reuse=true, tfo=true, ecn=true, shadow-tls-password=${SHADOW_TLS_PSK}, shadow-tls-sni=${SHADOW_TLS_SNI}, shadow-tls-version=3"
    else
        final_config_string="${AGENT_NAME} = snell, ${public_ip}, ${PUBLIC_PORT}, psk=${SNELL_PSK}, version=5, reuse=true, tfo=true, ecn=true"
    fi
    dialog --title "客户端配置信息" --msgbox "\n配置已生成。关闭此窗口后，配置信息将直接打印在终端中，以便于复制。\n\n${final_config_string}" 20 75
    clear
    echo -e "${Green}==================================================================${NC}"
    echo -e "${Yellow}请复制以下完整的客户端配置信息：${NC}"
    echo ""
    echo "${final_config_string}"
    echo ""
    echo -e "${Green}==================================================================${NC}"
    press_any_key
}

# =========================================================================
# !! 已优化 !! 8. 查看日志
# =========================================================================
view_log() {
    if ! $is_installed; then 
        dialog --title "提示" --msgbox "Snell 未安装。" 8 40
        return
    fi
    
    local services_to_log
    if [[ "$INSTALL_MODE" == "full" ]]; then
        services_to_log="-u snell.service -u shadow-tls.service"
    else
        services_to_log="-u snell.service"
    fi
    
    clear
    echo -e "正在加载日志... ${Yellow}(使用箭头滚动，按 'q' 键退出返回菜单)${NC}"
    sleep 1 # 确保用户能看到提示信息
    
    # 使用 journalctl 的默认分页器，并跳转到日志末尾
    # 用户可以自由滚动，按 'q' 即可退出
    # shellcheck disable=SC2086
    journalctl -e $services_to_log

    # 退出后直接返回主菜单，无需再按键
}

update_script() {
    echo "正在检查更新..."
    local new_version
    new_version=$(curl -sL "${SCRIPT_URL}" | grep 'SCRIPT_VERSION=' | head -1 | awk -F'"' '{print $2}')
    if [[ -z "$new_version" || "$new_version" == "user/repo/branch/snell_manager.sh" ]]; then
        echo -e "${Red}获取新版本信息失败。请检查脚本内的 SCRIPT_URL。${NC}"
        press_any_key
        return
    fi
    if [[ "$new_version" == "$SCRIPT_VERSION" ]]; then
        echo -e "${Green}当前已是最新版本 (${SCRIPT_VERSION})！${NC}"
    else
        echo -e "${Yellow}发现新版本: ${new_version}，正在更新...${NC}"
        local script_path="$0"
        if ! curl -sL "${SCRIPT_URL}" -o "${script_path}"; then
            echo -e "${Red}下载新脚本失败！${NC}"; press_any_key; return
        fi
        chmod +x "${script_path}"
        echo -e "${Green}脚本已更新至 ${new_version}！正在重新运行...${NC}"
        sleep 2
        exec "${script_path}"
    fi
    press_any_key
}

# 显示主菜单
show_menu() {
    check_status
    clear
    local status_text
    if $is_installed; then
        status_text="已安装 [${snell_version_installed}]"
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
    echo -e "${Green}2.${NC} 卸载 Snell Server"
    echo -e "-------------------------------------------------"
    echo -e "${Green}3.${NC} 启动 Snell Server"
    echo -e "${Green}4.${NC} 停止 Snell Server"
    echo -e "${Green}5.${NC} 重启 Snell Server"
    echo -e "-------------------------------------------------"
    echo -e "${Green}6.${NC} 修改配置信息  (同安装)"
    echo -e "${Green}7.${NC} 查看配置信息"
    echo -e "${Green}8.${NC} 查看运行状态  (日志)"
    echo -e "-------------------------------------------------"
    echo -e "${Green}9.${NC} 退出脚本"
    echo -e "================================================="
    echo -e "当前状态：${status_text}"
    echo
}

# --- 主逻辑 ---
main() {
    check_root
    install_dependencies
    while true; do
        show_menu
        read -p "请输入数字 [0-9]: " choice
        case "$choice" in
            0) update_script ;;
            1|6) do_install ;;
            2) do_uninstall ;;
            3) do_start ;;
            4) do_stop ;;
            5) do_restart; press_any_key ;;
            7) view_config ;;
            8) view_log ;;
            9) exit 0 ;;
            *) echo -e "${Red}无效输入，请输入 0-9 之间的数字。${NC}"; sleep 1 ;;
        esac
    done
}

main
