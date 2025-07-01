#!/bin/bash

# ==============================================================================
# Snell Server 全功能管理脚本 (定制版-GOOGOLE AI 生成)
#
# v2.8.1: 
# - 新增功能：Snell Server 版本更新 (菜单项 2)
# - 优化：安装时将实际版本号写入配置文件，以实现精确的版本跟踪
# - 优化：自动从 Snell 发布页获取最新版本号
# - 调整：重排菜单项
#
# v2.6.5: 初始版本
#
# 特性:
# - TUI 菜单式管理界面
# - 采用用户指定的 Snell 和 Shadow-TLS 原始配置
# - 支持安装、卸载、启动、停止、重启服务
# - 新增: 一键更新 Snell Server 版本
# - 可选安装模式 (Snell-only 或 Snell + Shadow-TLS)
# - 自动检测运行状态
# - 持久化配置，方便管理
# - 一键更新脚本
# ==============================================================================

# ==================== 终极乱码解决方案 ====================
# 1. 设置 LANG/LC_ALL 为 UTF-8，确保中文字符内容正确显示。
# 2. 设置 NCURSES_NO_UTF8_ACS=1，强制使用兼容性最好的方式绘制 dialog 边框，
#    解决因终端类型不支持UTF-8画线字符而导致的边框乱码问题。
# ==========================================================
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
export NCURSES_NO_UTF8_ACS=1

# --- 全局变量和常量 ---
SCRIPT_VERSION="2.8.1"
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
# ## 修改 ## SNELL_URL 现在会动态生成，这里作为备用
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
snell_version_installed="" # ## 修改 ## 这个变量将从配置文件读取

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
        # 适应不同的包管理器
        if command -v apt-get &> /dev/null; then
            apt-get update >/dev/null 2>&1
            apt-get install -y dialog curl wget unzip >/dev/null 2>&1
        elif command -v yum &> /dev/null; then
            yum install -y dialog curl wget unzip >/dev/null 2>&1
        elif command -v dnf &> /dev/null; then
            dnf install -y dialog curl wget unzip >/dev/null 2>&1
        else
            echo -e "${Red}无法确定包管理器，请手动安装: dialog, curl, wget, unzip${NC}"
            exit 1
        fi
    fi
}

load_config() {
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_CONFIG_FILE"
        # ## 修改 ## 从配置文件加载已安装的版本号
        snell_version_installed=$SNELL_VERSION_INSTALLED
    fi
}

check_status() {
    load_config
    if [[ -f "$SNELL_INSTALL_DIR/snell-server" && -f "$SNELL_CONFIG_FILE" ]]; then
        is_installed=true

        # ==================== 核心修复点 ====================
        # 如果从配置文件中未能加载到版本号 (兼容旧版安装)
        # 则使用脚本中定义的默认安装版本作为备用显示。
        if [[ -z "$snell_version_installed" ]]; then
            snell_version_installed="$SNELL_VERSION_FOR_INSTALL"
        fi
        # ======================================================

    else
        is_installed=false
        is_running=false
        snell_version_installed=""
        return
    fi

    if systemctl is-active --quiet snell.service; then
        if [[ "$INSTALL_MODE" == "full" ]]; then
            if systemctl is-active --quiet shadow-tls.service; then is_running=true; else is_running=false; fi
        else
            is_running=true
        fi
    else
        is_running=false
    fi
}

# --- 核心功能函数 ---

## 新增函数 ## - 获取 Snell 最新版本号
get_latest_snell_version() {
    # 从 Snell 发布说明页面抓取最新版本号
    # ==================== 最终解决方案 (v5) ====================
    # 根据用户反馈，最可靠的版本号来源是页面中的下载链接本身。
    # 此方法直接从所有下载链接中提取版本号，进行版本排序，并取最新一个。
    # 这是最稳定和精确的方法。
    #
    # 1. curl: 下载网页内容。
    # 2. grep -oP '(?<=snell-server-)v[^-]+':
    #    - 使用Perl正则，精确提取 "snell-server-" 之后，下一个连字符 "-" 之前的部分。
    #    - 这样就能直接得到如 "v5.0.0b1" 或 "v4.1.1" 这样的版本字符串。
    # 3. sort -uV:
    #    - -u: 去除重复行 (因为有amd64, i386等多个链接)。
    #    - -V: 按版本号进行排序 (例如 v5 > v4)。
    # 4. tail -n 1:
    #    - 取出排序后列表的最后一行，即为最新版本。
    # =========================================================
    local version
    version=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[^-]+' | sort -uV | tail -n 1)

    if [[ -z "$version" ]]; then
        # 如果此方法失败，说明页面结构发生重大变化或网络问题。
        echo "error"
    else
        # 直接返回从URL中提取的精确版本号
        echo "$version"
    fi
}


do_install() {
    local title="安装 Snell Server"
    if $is_installed; then
        title="修改配置"
        dialog --title "$title" --yesno "您已安装 Snell。要重新配置吗？\n\n这将覆盖现有设置并重启服务。" 10 50
        if [[ $? -ne 0 ]]; then return; fi
    fi

    # ... [do_install 函数的其余部分保持不变，除了最后写入配置文件的部分] ...
    
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
            "节点名称:"                  1 1 "$agent_name"      1 28 40 0
            "Shadow-TLS 端口 (对外):"    2 1 "$public_port"     2 28 40 0
            "Snell 内部端口:"              3 1 "$snell_port"      3 28 40 0
            "Shadow-TLS 伪装域名:"      4 1 "$shadow_tls_sni"  4 28 40 0
        )
    else
        form_items=(
            "节点名称:"          1 1 "$agent_name" 1 28 40 0
            "Snell 端口 (对外):" 2 1 "$snell_port"  2 28 40 0
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
    mkdir -p "$SNELL_INSTALL_DIR"

    echo "正在下载 Snell Server..."
    local temp_zip; temp_zip=$(mktemp)
    # ## 修改 ## 使用动态生成的 URL
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
        if [[ ! -f "$SNELL_INSTALL_DIR/shadow-tls" ]]; then
            dialog --title "错误" --msgbox "Shadow-TLS 安装失败！\n\n无法在 $SNELL_INSTALL_DIR 中找到文件 'shadow-tls'。" 12 70; return 1
        fi
        chmod +x "$SNELL_INSTALL_DIR/shadow-tls"; echo -e "${Green}Shadow-TLS 二进制文件准备就绪。${NC}"
    fi

    echo "所有二进制文件验证通过，正在写入配置文件..."
    SNELL_PSK=$(openssl rand -base64 18)
    local SHADOW_TLS_PSK=""; if [[ "$INSTALL_MODE" == "full" ]]; then SHADOW_TLS_PSK=$(openssl rand -base64 18); fi
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
    
    # ## 修改 ## 将安装版本也写入配置文件
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
    
    check_status
    do_restart
    
    clear
    echo -e "${Green}安装/配置成功完成！${NC}"
    view_config
}

## 新增函数 ## - 更新 Snell Server 版本
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
    # 使用 sed 安全地替换版本号
    sed -i "s/^SNELL_VERSION_INSTALLED=.*/SNELL_VERSION_INSTALLED=\"${remote_version}\"/" "$SCRIPT_CONFIG_FILE"
    
    echo "正在重启服务以应用更新..."
    do_restart
    
    check_status # 重新检查状态以更新显示
    echo -e "${Green}Snell Server 已成功更新至 ${remote_version}！${NC}"
    press_any_key
}


do_uninstall() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
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
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    if $is_running; then dialog --title "提示" --msgbox "Snell 已在运行中。" 8 40; return; fi
    echo "正在启动服务..."; systemctl start snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl start shadow-tls.service; fi
    sleep 1; check_status
    if $is_running; then echo -e "${Green}启动成功！${NC}"; else echo -e "${Red}启动失败。${NC}"; fi
    press_any_key
}

do_stop() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    if ! $is_running; then dialog --title "提示" --msgbox "Snell 未运行。" 8 40; return; fi
    echo "正在停止服务..."; systemctl stop snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl stop shadow-tls.service; fi
    sleep 1; echo -e "${Green}服务已停止。${NC}"; press_any_key
}

do_restart() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    echo "正在重启服务..."; systemctl restart snell.service
    if [[ "$INSTALL_MODE" == "full" ]]; then systemctl restart shadow-tls.service; fi
    sleep 1; check_status
    if $is_running; then echo -e "${Green}重启成功！${NC}"; else echo -e "${Red}重启失败。${NC}"; fi
}

view_config() {
    if ! $is_installed; then dialog --title "提示" --msgbox "Snell 未安装。" 8 40; return; fi
    load_config
    
    # ## 修改 ## 使用实际安装的版本号来生成配置
    local temp_version=${snell_version_installed#v}
    local snell_major_version=${temp_version:0:1}

    local public_ip; public_ip=$(curl -s4 ifconfig.me)
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
    # ... [此函数保持不变] ...
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
    # ... [此函数保持不变] ...
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

# ## 修改 ## - 更新主菜单显示
show_menu() {
    check_status; clear
    local mode_display_text=""
    if $is_installed; then
        if [[ "$INSTALL_MODE" == "full" ]]; then mode_display_text=" (Snell + Shadow-TLS)";
        elif [[ "$INSTALL_MODE" == "snell_only" ]]; then mode_display_text=" (仅 Snell)"; fi
    fi
    local status_text
    if $is_installed; then
        # 使用 snell_version_installed 变量显示
        status_text="已安装 [${snell_version_installed}]${mode_display_text}"
        if $is_running; then status_text="${Green}${status_text} 并已启动${NC}";
        else status_text="${Red}${status_text} 但未启动${NC}"; fi
    else
        status_text="${Red}未安装${NC}"
    fi
    echo -e "Snell Server 管理脚本 [v${SCRIPT_VERSION}]"
    echo -e "================================================="
    echo -e "${Green}0.${NC} 更新脚本"
    echo -e "-------------------------------------------------"
    echo -e "${Green}1.${NC} 安装 Snell Server"
    echo -e "${Yellow}2.${NC} 更新 Snell 版本" # 新增
    echo -e "${Green}3.${NC} 卸载 Snell Server" # 序号+1
    echo -e "-------------------------------------------------"
    echo -e "${Green}4.${NC} 启动 Snell Server" # 序号+1
    echo -e "${Green}5.${NC} 停止 Snell Server" # 序号+1
    echo -e "${Green}6.${NC} 重启 Snell Server" # 序号+1
    echo -e "-------------------------------------------------"
    echo -e "${Green}7.${NC} 修改配置信息  (同安装)" # 序号+1
    echo -e "${Green}8.${NC} 查看配置信息" # 序号+1
    echo -e "${Green}9.${NC} 查看运行状态  (日志)" # 序号+1
    echo -e "-------------------------------------------------"
    echo -e "${Green}10.${NC} 退出脚本" # 序号+1
    echo -e "================================================="
    echo -e "当前状态：${status_text}\n"
}

# ## 修改 ## - 更新主循环逻辑
main() {
    check_root
    install_dependencies
    while true; do
        show_menu
        read -p "请输入数字 [0-10]: " choice
        case "$choice" in
            0) update_script ;; 
            1) do_install ;; 
            2) do_update_snell ;; # 新增
            3) do_uninstall ;;    # 序号+1
            4) do_start ;;         # 序号+1
            5) do_stop ;;          # 序号+1
            6) do_restart; press_any_key ;; # 序号+1
            7) do_install ;;       # 序号+1 (修改配置)
            8) view_config ;;      # 序号+1
            9) view_log ;;         # 序号+1
            10) exit 0 ;;          # 序号+1 (退出)
            *) echo -e "${Red}无效输入。${NC}"; sleep 1 ;;
        esac
    done
}

main
