#!/bin/bash

# ==============================================================================
# Snell Server 全功能管理脚本 (定制版-GOOGLE AI 生成)
#
# v3.5.11:
# - 修复: 自更新通过最新提交号下载，避开 Raw 分支地址缓存。
# - 修复: 版本检测与更新使用同一份已验证脚本，替换失败时保留原文件。
#
# v3.5.10:
# - 修复: 所有文字样式显式指定黑色背景，避免浅色终端出现白色色块。
# - 调整: 提高正文亮度，清屏前先设置控制台底色。
#
# v3.5.9:
# - 新增: 从官方发布标题提取全部版本，并加入仓库 v3.0.1 兼容版。
# - 修复: 按架构选择下载包，按目标版本迁移 DNS、监听地址及 mode。
# - 调整: 黑底荧光绿终端界面及统一弹窗配色。
#
# v3.5.8:
# - 修复: 实例编号冲突、版本切换配置迁移及失败恢复。
# - 修复: 实例选择、重启结果及十进制端口校验。
# - 调整: 使用 00 退出脚本。
#
# v3.5.7:
# - 修复: IPv4+IPv6 配置完成后输出单条双栈客户端节点信息。
#
# v3.5.6:
# - 新增: 安装和修改配置时支持选择 IPv4、IPv6、IPv4+IPv6。
# - 新增: 安装菜单版本号从 Surge 官方 Snell release notes 动态获取。
#
# v3.5.5:
# - 修复: 增加端口校验、依赖逐项检查、配置白名单读取和卸载路径保护。
# - 修复: 增强下载解压检查、公网 IP 获取失败兜底和脚本自更新检查。
#
# v3.5.4:
# - 新增: 支持安装和管理 Snell v6.0.0 RC 服务端。
# - 新增: Snell v6 支持 mode 参数 (default/unshaped/unsafe-raw)。
#
# v3.5.3:
# - 新增: 自动创建快捷别名。首次安装成功后，会自动在 .bashrc/.zshrc 中创建快捷命令 's'。
# - 新增: 跨 VPS 安装次数统计。通过向指定服务器端点发送匿名报告实现。
#
# v3.5.2:
# - 新增: 增加了脚本使用次数统计功能，包括总计使用次数和本日使用次数。
#
# v3.5.1:
# - 修复: 修正了 v3 特殊版安装逻辑，确保版本号和标志位正确。
#
# 特性:
# - TUI 菜单式管理界面
# - 强大的多实例管理（安装、修改、卸载、启停、查看）
# - 精简安装 (仅 Snell)
# - 支持安装、卸载、启动、停止、重启服务
# - 一键更新/更换 Snell Server 版本
# - 自动检测运行状态
# - 持久化配置，方便管理
# - 一键更新脚本
# - 使用次数统计 (本地 & 远程)
# - 自动创建快捷命令
# ==============================================================================

# --- 全局变量和常量 ---
SCRIPT_VERSION="3.5.11"
SNELL_VERSION_FOR_INSTALL="v5.0.1" # 官网版本获取失败时的默认稳定版本
SNELL_V6_VERSION_FOR_INSTALL="v6.0.0rc" # Snell v6 当前官方 RC 版本

# --- 文件路径 (将在运行时动态生成) ---
SNELL_INSTALL_DIR="/usr/local/bin"
SNELL_CONFIG_DIR=""
SNELL_CONFIG_FILE=""
SNELL_SERVICE_FILE=""
SCRIPT_CONFIG_FILE=""
SNELL_BINARY_NAME=""
SNELL_SERVICE_NAME=""
USAGE_CONFIG_DIR="/etc/snell-manager"
USAGE_CONFIG_FILE="${USAGE_CONFIG_DIR}/usage.conf"
FIRST_RUN_MARKER_FILE="${USAGE_CONFIG_DIR}/.install_reported" # 首次运行报告的标记文件

# --- 下载链接 ---
SNELL_RELEASE_NOTES_URL="https://kb.nssurge.com/surge-knowledge-base/release-notes/snell"
SCRIPT_URL="https://raw.githubusercontent.com/mobosang/chnroute/main/snell-ai.sh"
SCRIPT_REF_API_URL="https://api.github.com/repos/mobosang/chnroute/git/ref/heads/main"
SNELL_V3_SPECIAL_URL="https://raw.githubusercontent.com/mobosang/chnroute/main/snell-server-v3.0.1-linux-amd64.zip"
SNELL_V3_SPECIAL_ARM64_URL="https://raw.githubusercontent.com/mobosang/chnroute/main/snell-server-v3.0.1-linux-arm64.zip"
# 【【【 重要配置 】】】 请将下面的 URL 替换为您自己的服务器端点
COUNTER_ENDPOINT_URL="http://your-server-domain.com/counter.php"


# --- 颜色定义 ---
# 每个样式都同时设置前景与背景；SGR 0 会恢复用户终端的默认底色。
Green="\033[0;1;32;40m"
Red="\033[0;1;31;40m"
Yellow="\033[0;1;33;40m"
Cyan="\033[0;1;36;40m"
Dim="\033[0;32;40m"
NC="\033[0;97;40m"
UI_THEME_FILE=""

# --- 状态变量 ---
instance_suffix="" # 后缀, e.g., "" for default, "-2", "-3"
total_usage_count=0 # 总计使用次数
today_usage_count=0 # 本日使用次数
latest_snell_version_cache=""
latest_snell_v6_version_cache=""
CHANGE_DIR=""
CHANGE_PATHS=()
CHANGE_WAS_RUNNING=false

# --- 工具函数 ---
cleanup_ui() {
    [[ -z "$UI_THEME_FILE" ]] || rm -f "$UI_THEME_FILE"
    if [[ -t 1 ]]; then printf '\033[0m'; fi
}

setup_ui() {
    [[ -t 1 ]] || return 0
    UI_THEME_FILE=$(mktemp) || return 0
    cat > "$UI_THEME_FILE" <<'EOF'
use_shadow = OFF
use_colors = ON
screen_color = (GREEN,BLACK,OFF)
dialog_color = (GREEN,BLACK,OFF)
title_color = (GREEN,BLACK,ON)
border_color = (GREEN,BLACK,ON)
border2_color = (GREEN,BLACK,OFF)
button_active_color = (BLACK,GREEN,ON)
button_inactive_color = (GREEN,BLACK,OFF)
button_key_active_color = (BLACK,GREEN,ON)
button_key_inactive_color = (CYAN,BLACK,ON)
button_label_active_color = (BLACK,GREEN,ON)
button_label_inactive_color = (GREEN,BLACK,OFF)
inputbox_color = (CYAN,BLACK,ON)
inputbox_border_color = (GREEN,BLACK,OFF)
inputbox_border2_color = (GREEN,BLACK,OFF)
menubox_color = (GREEN,BLACK,OFF)
menubox_border_color = (GREEN,BLACK,OFF)
menubox_border2_color = (GREEN,BLACK,OFF)
form_active_text_color = (BLACK,GREEN,ON)
form_text_color = (CYAN,BLACK,ON)
form_item_readonly_color = (GREEN,BLACK,OFF)
item_color = (GREEN,BLACK,OFF)
item_selected_color = (BLACK,GREEN,ON)
tag_color = (CYAN,BLACK,ON)
tag_selected_color = (BLACK,GREEN,ON)
tag_key_color = (CYAN,BLACK,ON)
tag_key_selected_color = (BLACK,GREEN,ON)
check_color = (GREEN,BLACK,OFF)
check_selected_color = (BLACK,GREEN,ON)
uarrow_color = (GREEN,BLACK,ON)
darrow_color = (GREEN,BLACK,ON)
EOF
    export DIALOGRC="$UI_THEME_FILE"
    trap cleanup_ui EXIT
}

press_any_key() {
    echo -e "\n${Dim}[ enter console ]${NC} ${Green}按任意键返回主菜单...${NC}"
    read -r -n 1 -s
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${Red}错误：此脚本必须以 root 权限运行。${NC}"
        exit 1
    fi
}

load_manager_config() {
    local config_file="${1:-$SCRIPT_CONFIG_FILE}"
    if [[ ! -f "$config_file" ]]; then
        return 1
    fi

    AGENT_NAME=""
    SNELL_PORT=""
    SNELL_PSK=""
    SNELL_VERSION_INSTALLED=""
    IS_V3_SPECIAL=""
    SNELL_MODE=""
    SNELL_IP_STACK=""
    INSTANCE_SUFFIX=""

    local key value
    while IFS='=' read -r key value; do
        value=${value%$'\r'}
        if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
            value="${value:1:${#value}-2}"
        fi

        case "$key" in
            AGENT_NAME|SNELL_PORT|SNELL_PSK|SNELL_VERSION_INSTALLED|IS_V3_SPECIAL|SNELL_MODE|SNELL_IP_STACK|INSTANCE_SUFFIX)
                printf -v "$key" '%s' "$value"
                ;;
        esac
    done < "$config_file"
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535))
}

validate_ip_stack() {
    local ip_stack="$1"
    [[ "$ip_stack" =~ ^(ipv4|ipv6|ipv4\+ipv6)$ ]]
}

get_snell_listen_address() {
    local ip_stack="$1"
    case "$ip_stack" in
        ipv6) echo "[::]" ;;
        ipv4+ipv6) echo "[::]" ;;
        *) echo "0.0.0.0" ;;
    esac
}

get_snell_ipv6_enabled() {
    local ip_stack="$1"
    case "$ip_stack" in
        ipv6|ipv4+ipv6) echo "true" ;;
        *) echo "false" ;;
    esac
}

download_snell_binary() {
    local download_url="$1"
    local target_path="$2"
    local temp_zip temp_unzip_dir
    temp_zip=$(mktemp)
    temp_unzip_dir=$(mktemp -d)

    if ! wget --timeout=30 --tries=3 -qO "$temp_zip" "$download_url"; then
        rm -f "$temp_zip"
        rm -rf "$temp_unzip_dir"
        return 1
    fi

    if ! unzip -qo "$temp_zip" -d "$temp_unzip_dir"; then
        rm -f "$temp_zip"
        rm -rf "$temp_unzip_dir"
        return 1
    fi

    rm -f "$temp_zip"
    if [[ ! -f "${temp_unzip_dir}/snell-server" ]]; then
        rm -rf "$temp_unzip_dir"
        return 1
    fi

    if ! mv "${temp_unzip_dir}/snell-server" "$target_path"; then
        rm -rf "$temp_unzip_dir"
        return 1
    fi
    rm -rf "$temp_unzip_dir"
}

is_safe_instance_path() {
    local path="$1"
    [[ -n "$path" && "$path" =~ ^/etc/snell(-[0-9]+)?$ ]]
}

# 先下载、备份，再停服替换；事务仅覆盖当前实例的四个文件。
prepare_instance_change() {
    local download_url="$1" path i=0
    mkdir -p "$SNELL_INSTALL_DIR" || return 1
    CHANGE_DIR=$(mktemp -d "${SNELL_INSTALL_DIR}/.snell-change.XXXXXX") || return 1
    CHANGE_PATHS=("${SNELL_INSTALL_DIR}/${SNELL_BINARY_NAME}" "$SNELL_CONFIG_FILE" "$SCRIPT_CONFIG_FILE" "$SNELL_SERVICE_FILE")
    if ! download_snell_binary "$download_url" "$CHANGE_DIR/new-binary" ||
        ! chmod +x "$CHANGE_DIR/new-binary" ||
        ! "$CHANGE_DIR/new-binary" --help >/dev/null 2>&1; then
        echo "下载包不可用，或二进制与当前架构/运行库不兼容；未停止原服务。" >&2
        rm -rf "$CHANGE_DIR"
        return 1
    fi
    for path in "${CHANGE_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            if ! cp -p "$path" "$CHANGE_DIR/backup-$i"; then
                rm -rf "$CHANGE_DIR"
                return 1
            fi
        fi
        i=$((i + 1))
    done
    CHANGE_WAS_RUNNING=false
    if systemctl is-active --quiet "$SNELL_SERVICE_NAME"; then
        CHANGE_WAS_RUNNING=true
    fi
    if [[ -f "$SNELL_SERVICE_FILE" ]] && ! systemctl stop "$SNELL_SERVICE_NAME"; then
        rm -rf "$CHANGE_DIR"
        return 1
    fi
    if ! mv "$CHANGE_DIR/new-binary" "${SNELL_INSTALL_DIR}/${SNELL_BINARY_NAME}"; then
        rollback_instance_change
        return 1
    fi
}

rollback_instance_change() {
    local path i=0 failed=false
    systemctl stop "$SNELL_SERVICE_NAME" >/dev/null 2>&1
    for path in "${CHANGE_PATHS[@]}"; do
        if [[ -e "$CHANGE_DIR/backup-$i" ]]; then
            cp -p "$CHANGE_DIR/backup-$i" "$path" || failed=true
        else
            rm -f "$path" || failed=true
        fi
        i=$((i + 1))
    done
    systemctl daemon-reload || failed=true
    if [[ "$CHANGE_WAS_RUNNING" == true ]]; then
        systemctl start "$SNELL_SERVICE_NAME" || failed=true
        sleep 1
        systemctl is-active --quiet "$SNELL_SERVICE_NAME" || failed=true
    fi
    if [[ "$failed" == true ]]; then
        echo -e "${Red}自动恢复失败，请检查服务；原文件备份保留在 ${CHANGE_DIR}${NC}"
        return 1
    fi
    rm -rf "$CHANGE_DIR"
    echo -e "${Yellow}已恢复此实例原有文件及运行状态。${NC}"
}

finish_instance_change() {
    if ! do_restart; then
        rollback_instance_change
        return 1
    fi
    rm -rf "$CHANGE_DIR"
}

validate_snell_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-]?(alpha|beta|rc)[0-9.]*)?$ ]]
}

check_supported_snell_version() {
    validate_snell_version "$1" || return 1
    case "$1" in
        v3.0.1|v4.*|v5.*|v6.*) return 0 ;;
        *) echo "尚未适配此版本的安装配置: $1" >&2; return 1 ;;
    esac
}

get_linux_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo aarch64 ;;
        i386|i486|i586|i686) echo i386 ;;
        armv7l) echo armv7l ;;
        *) echo "不支持的 CPU 架构: $(uname -m)" >&2; return 1 ;;
    esac
}

get_snell_download_url() {
    local version="$1" arch
    check_supported_snell_version "$version" || return 1
    arch=$(get_linux_arch) || return 1
    if [[ "$version" == v3.0.1 ]]; then
        case "$arch" in
            amd64) echo "$SNELL_V3_SPECIAL_URL" ;;
            aarch64) echo "$SNELL_V3_SPECIAL_ARM64_URL" ;;
            *) echo "仓库 v3.0.1 兼容版仅提供 amd64 和 arm64 包。" >&2; return 1 ;;
        esac
    else
        echo "https://dl.nssurge.com/snell/snell-server-${version}-linux-${arch}.zip"
    fi
}

snell_supports_custom_dns() {
    case "$1" in v3.*|v4.0.*) return 1 ;; *) return 0 ;; esac
}

get_version_listen_value() {
    local version="$1" port="$2" ip_stack="$3"
    if [[ "$version" == v6* && "$ip_stack" == ipv4+ipv6 ]]; then
        echo "0.0.0.0:$port, [::]:$port"
    elif [[ "$version" == v4* && "$ip_stack" != ipv4 ]]; then
        # 官方 v4 的解析器要求裸 IPv6，使用 [::]:port 会报 Invalid listen address。
        echo ":::$port"
    else
        echo "$(get_snell_listen_address "$ip_stack"):$port"
    fi
}

get_version_install_note() {
    case "$1" in
        v3.0.1) echo "仓库 Open-snell 兼容版；单地址监听；系统 DNS" ;;
        v4.0.*) echo "官方 v4；单地址监听；系统 DNS" ;;
        v4.*) echo "官方 v4；单地址监听；支持自定义 DNS" ;;
        v5.*) echo "官方 v5；单地址监听；QUIC 需 TCP/UDP 端口" ;;
        v6.*) echo "官方 v6；支持 mode 和双地址监听" ;;
        *) echo "官方页面所列版本；尚未适配安装配置" ;;
    esac
}

migrate_version_config() {
    local target_version="$1" effective_mode listen_address
    check_supported_snell_version "$target_version" || return 1
    validate_port "$SNELL_PORT" || return 1
    local port=$((10#$SNELL_PORT)) ip_stack=${SNELL_IP_STACK:-ipv4}
    validate_ip_stack "$ip_stack" || return 1
    listen_address=$(get_version_listen_value "$target_version" "$port" "$ip_stack")
    sed -i "s/^listen = .*/listen = ${listen_address}/" "$SNELL_CONFIG_FILE" || return 1
    # 服务端当前配置是实际生效值，管理配置必须与其保持一致。
    effective_mode=$(sed -n 's/^[[:space:]]*mode[[:space:]]*=[[:space:]]*//p' "$SNELL_CONFIG_FILE" | head -n 1)
    effective_mode=${effective_mode%$'\r'}
    effective_mode=${effective_mode%%[[:space:]#;]*}
    effective_mode=${effective_mode:-default}
    if [[ "$target_version" == v6* ]]; then
        [[ "$effective_mode" =~ ^(default|unshaped|unsafe-raw)$ ]] || return 1
    else
        effective_mode=default
    fi
    sed -i '/^[[:space:]]*mode[[:space:]]*=/d' "$SNELL_CONFIG_FILE" || return 1
    if [[ "$target_version" == v6* ]]; then
        echo "mode = $effective_mode" >> "$SNELL_CONFIG_FILE" || return 1
    else
        sed -i '/^[[:space:]]*\(dns-ip-preference\|ipv-preference\)[[:space:]]*=/d' "$SNELL_CONFIG_FILE" || return 1
    fi
    if [[ "$target_version" != v5* && "$target_version" != v6* ]]; then
        sed -i '/^[[:space:]]*egress-interface[[:space:]]*=/d' "$SNELL_CONFIG_FILE" || return 1
    fi
    if ! snell_supports_custom_dns "$target_version"; then
        sed -i '/^[[:space:]]*dns[[:space:]]*=/d' "$SNELL_CONFIG_FILE" || return 1
    elif ! grep -q '^[[:space:]]*dns[[:space:]]*=' "$SNELL_CONFIG_FILE"; then
        echo 'dns = 1.1.1.1, 9.9.9.9' >> "$SNELL_CONFIG_FILE" || return 1
    fi
    sed -i '/^SNELL_MODE=/d' "$SCRIPT_CONFIG_FILE" || return 1
    echo "SNELL_MODE=\"$effective_mode\"" >> "$SCRIPT_CONFIG_FILE" || return 1
    local special_flag=false
    [[ "$target_version" != v3.0.1 ]] || special_flag=true
    sed -i -e '/^SNELL_VERSION_INSTALLED=/d' -e '/^IS_V3_SPECIAL=/d' "$SCRIPT_CONFIG_FILE" || return 1
    printf 'SNELL_VERSION_INSTALLED="%s"\nIS_V3_SPECIAL=%s\n' "$target_version" "$special_flag" >> "$SCRIPT_CONFIG_FILE"
}

report_first_run() {
    # 如果标记文件已存在，说明已经报告过，直接退出函数
    if [[ -f "$FIRST_RUN_MARKER_FILE" ]]; then
        return
    fi
    # 如果URL未配置，也直接退出
    if [[ "$COUNTER_ENDPOINT_URL" == "http://your-server-domain.com/counter.php" ]]; then
        return
    fi

    echo "首次运行，正在向开发者服务器匿名报告安装..."
    if curl --connect-timeout 5 -s -o /dev/null "$COUNTER_ENDPOINT_URL"; then
        echo "报告成功。这只会在首次运行时发生一次。"
        mkdir -p "$USAGE_CONFIG_DIR"
        touch "$FIRST_RUN_MARKER_FILE"
    else
        echo "报告失败，可能是网络问题。脚本将继续正常运行。"
    fi
    echo "-------------------------------------------------"
    sleep 1
}

update_usage_stats() {
    mkdir -p "$USAGE_CONFIG_DIR"
    local current_date=$(date +%Y-%m-%d)
    
    if [[ ! -f "$USAGE_CONFIG_FILE" ]]; then
        echo "TOTAL_USAGE=1" > "$USAGE_CONFIG_FILE"
        echo "TODAY_USAGE=1" >> "$USAGE_CONFIG_FILE"
        echo "LAST_USED_DATE=${current_date}" >> "$USAGE_CONFIG_FILE"
        total_usage_count=1; today_usage_count=1; return
    fi

    local last_total_usage=$(grep '^TOTAL_USAGE=' "$USAGE_CONFIG_FILE" | cut -d'=' -f2)
    local last_today_usage=$(grep '^TODAY_USAGE=' "$USAGE_CONFIG_FILE" | cut -d'=' -f2)
    local last_used_date=$(grep '^LAST_USED_DATE=' "$USAGE_CONFIG_FILE" | cut -d'=' -f2)

    last_total_usage=${last_total_usage:-0}; last_today_usage=${last_today_usage:-0}
    total_usage_count=$((last_total_usage + 1))

    if [[ "$current_date" == "$last_used_date" ]]; then
        today_usage_count=$((last_today_usage + 1))
    else
        today_usage_count=1
    fi

    local temp_stat_file=$(mktemp)
    {
        echo "TOTAL_USAGE=${total_usage_count}"
        echo "TODAY_USAGE=${today_usage_count}"
        echo "LAST_USED_DATE=${current_date}"
    } > "$temp_stat_file"
    mv "$temp_stat_file" "$USAGE_CONFIG_FILE"
}

setup_alias() {
    local alias_name="s" # 你想设置的别名
    local script_path; script_path=$(realpath "$0") # 获取脚本自身的绝对路径
    local shell_config_file=""

    if [[ "$SHELL" == *"bash"* ]]; then
        shell_config_file="$HOME/.bashrc"
    elif [[ "$SHELL" == *"zsh"* ]]; then
        shell_config_file="$HOME/.zshrc"
    else
        return
    fi
    
    if [[ ! -f "$shell_config_file" ]]; then
        return
    fi

    if ! grep -q "alias ${alias_name}='${script_path}'" "$shell_config_file"; then
        echo "正在为您创建快捷命令..."
        cat >> "$shell_config_file" << EOF

# Snell Manager Script Alias (auto-generated by script)
alias ${alias_name}='${script_path}'
EOF
        echo -e "${Green}快捷命令 '${alias_name}' 已创建成功！${NC}"
        echo -e "${Yellow}请运行 'source ${shell_config_file}' 或重新登录以使其生效。${NC}"
        echo -e "${Yellow}之后您就可以直接输入 '${alias_name}' 来运行此脚本了。${NC}"
        sleep 3
    fi
}

# 动态设置路径
setup_paths() {
    local suffix="$1"
    instance_suffix=$suffix
    SNELL_CONFIG_DIR="/etc/snell${suffix}"
    SNELL_CONFIG_FILE="${SNELL_CONFIG_DIR}/snell-server.conf"
    SNELL_SERVICE_NAME="snell${suffix}.service"
    SNELL_SERVICE_FILE="/etc/systemd/system/${SNELL_SERVICE_NAME}"
    SCRIPT_CONFIG_FILE="${SNELL_CONFIG_DIR}/manager.conf"
    SNELL_BINARY_NAME="snell-server${suffix}"
}

select_snell_instance() {
    local title="$1"
    local existing_services
    existing_services=$(find /etc/systemd/system/ -maxdepth 1 -name "snell*.service" -exec basename {} \; 2>/dev/null | sort -V)

    if [[ -z "$existing_services" ]]; then
        dialog --title "错误" --msgbox "未找到任何已安装的 Snell 实例。\n\n请先使用选项 1、2 或 3 进行安装。" 10 50
        return 1
    fi

    local menu_items=()
    while IFS= read -r service_name; do
        local config_dir="/etc/${service_name%.service}"
        local agent_name="N/A"
        if [[ -f "${config_dir}/manager.conf" ]]; then
            agent_name=$(grep -oP 'AGENT_NAME="\K[^"]+' "${config_dir}/manager.conf")
        fi
        menu_items+=("$service_name" "节点名: $agent_name")
    done <<< "$existing_services"

    local choice
    choice=$(dialog --clear --backtitle "Snell 多实例管理" --title "$title" \
        --menu "请选择您要操作的 Snell 实例:" 20 70 15 "${menu_items[@]}" 3>&1 1>&2 2>&3)

    if [[ -z "$choice" ]]; then
        return 1 # User cancelled
    fi

    local suffix
    if [[ "$choice" == "snell.service" ]]; then
        suffix=""
    else
        suffix=$(echo "$choice" | sed -n 's/snell\(.*\)\.service/\1/p')
    fi
    
    setup_paths "$suffix"
    return 0
}


install_dependencies() {
    local deps=(dialog curl wget unzip openssl)
    local missing_deps=()
    local dep
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -eq 0 ]]; then return; fi

    echo "正在安装缺失依赖: ${missing_deps[*]}"
    if command -v apt-get &> /dev/null; then
        apt-get update >/dev/null 2>&1; apt-get install -y "${missing_deps[@]}" >/dev/null 2>&1
    elif command -v yum &> /dev/null; then
        yum install -y epel-release >/dev/null 2>&1; yum install -y "${missing_deps[@]}" >/dev/null 2>&1
    elif command -v dnf &> /dev/null; then
        dnf install -y epel-release >/dev/null 2>&1; dnf install -y "${missing_deps[@]}" >/dev/null 2>&1
    else
        echo -e "${Red}无法确定包管理器，请手动安装: dialog, curl, wget, unzip, openssl${NC}"; exit 1
    fi

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${Red}依赖安装失败或不可用: ${dep}${NC}"
            exit 1
        fi
    done
}

open_firewall_ports() {
    local port=$1; echo "正在配置防火墙以开放端口: ${port}/tcp and ${port}/udp"
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="${port}/tcp" --permanent >/dev/null 2>&1
        firewall-cmd --zone=public --add-port="${port}/udp" --permanent >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1; echo -e "${Green}firewalld 规则已添加。${NC}"
    elif command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${port}" >/dev/null 2>&1; ufw reload >/dev/null 2>&1; echo -e "${Green}ufw 规则已添加。${NC}"
    else
        echo -e "${Yellow}未检测到活动的 firewalld 或 ufw。请手动开放端口: ${port}${NC}"
    fi
}

check_selinux() {
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

# --- 核心功能函数 ---

get_latest_snell_version() {
    local version; version=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[^-]+' | sort -uV | tail -n 1)
    if [[ -z "$version" ]]; then echo "error"; else echo "$version"; fi
}

get_latest_stable_snell_version() {
    local version; version=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[0-9]+\.[0-9]+\.[0-9]+(?=-linux-)' | sort -uV | tail -n 1)
    if [[ -z "$version" ]]; then echo "error"; else echo "$version"; fi
}

get_latest_snell_v6_version() {
    local version; version=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v6[^-]+' | sort -uV | tail -n 1)
    if [[ -z "$version" ]]; then echo "error"; else echo "$version"; fi
}

get_install_snell_version() {
    if [[ -n "$latest_snell_version_cache" ]]; then
        echo "$latest_snell_version_cache"
        return
    fi

    local version; version=$(get_latest_stable_snell_version)
    if [[ "$version" == "error" || -z "$version" ]]; then
        latest_snell_version_cache="$SNELL_VERSION_FOR_INSTALL"
    else
        latest_snell_version_cache="$version"
    fi
    echo "$latest_snell_version_cache"
}

get_install_snell_v6_version() {
    if [[ -n "$latest_snell_v6_version_cache" ]]; then
        echo "$latest_snell_v6_version_cache"
        return
    fi

    local version; version=$(get_latest_snell_v6_version)
    if [[ "$version" == "error" || -z "$version" ]]; then
        latest_snell_v6_version_cache="$SNELL_V6_VERSION_FOR_INSTALL"
    else
        latest_snell_v6_version_cache="$version"
    fi
    echo "$latest_snell_v6_version_cache"
}

parse_release_versions() {
    # 仅取 Release Notes 的发布标题，不把正文中的 Surge 3.1.0 等引用当作服务端版本。
    awk '/^## Release Notes[[:space:]]*$/ { releases=1; next }
         releases && /^## / { exit }
         releases && /^### v[0-9]/ { print $2 }' |
        tr -d '\r' |
        grep -E '^v[0-9]+\.[0-9]+\.[0-9]+([.-]?(alpha|beta|rc)[0-9.]*)?$' |
        sort -urV
}

get_available_versions() {
    local page versions
    if ! page=$(curl -fsSL --connect-timeout 10 --max-time 30 "${SNELL_RELEASE_NOTES_URL}.md"); then
        echo "官方版本列表获取失败，本次仅提供仓库 v3.0.1 兼容版。" >&2
    else
        versions=$(printf '%s\n' "$page" | parse_release_versions)
        if [[ -z "$versions" ]]; then
            echo "官方页面未解析出发布标题，本次仅提供仓库 v3.0.1 兼容版。" >&2
        fi
    fi
    printf '%s\nv3.0.1\n' "$versions" | sed '/^$/d' | sort -urV
}

_install_or_modify_logic() {
    local install_version="$1"
    local download_url="$2"
    local special_flag="$3" # true or false for v3
    local mode="$4" # "new" or "modify"
    check_supported_snell_version "$install_version" || return 1
    local is_v6=false
    if [[ "$install_version" == v6* ]]; then
        is_v6=true
    fi

    if [[ "$mode" == "new" ]]; then
        local existing_services
        existing_services=$(find /etc/systemd/system/ -maxdepth 1 -name "snell*.service" -exec basename {} \; 2>/dev/null)
        
        if [[ -n "$existing_services" ]]; then
            local count; count=$(echo "$existing_services" | wc -l)
            local next_instance_num=2
            while [[ -e "/etc/systemd/system/snell-${next_instance_num}.service" ||
                     -e "/etc/snell-${next_instance_num}" ||
                     -e "${SNELL_INSTALL_DIR}/snell-server-${next_instance_num}" ]] ||
                  grep -Fxq "snell-${next_instance_num}.service" <<< "$existing_services"; do
                next_instance_num=$((next_instance_num + 1))
            done

            local choice; choice=$(dialog --clear --backtitle "安装检测" --title "检测到现有 Snell 服务" \
                --menu "系统上已存在 ${count} 个 Snell 服务实例。\n请选择您的操作:" 15 70 2 \
                "overwrite" "覆盖安装 (管理默认实例 snell.service)" \
                "coexist"   "共存安装 (创建新实例 snell-${next_instance_num}.service)" \
                3>&1 1>&2 2>&3)
            
            if [[ -z "$choice" ]]; then return 1; fi
            if [[ "$choice" == "coexist" ]]; then
                setup_paths "-${next_instance_num}"
                dialog --title "共存模式提示" --msgbox "您已选择【共存模式】。\n\n- 新服务名: ${SNELL_SERVICE_NAME}\n\n【重要】\n在接下来的配置中，您【必须】为新实例指定一个【完全不同】的端口号！" 15 70
            else
                setup_paths "" # Overwrite
                dialog --title "覆盖模式警告" --yesno "您已选择【覆盖安装】。\n\n这将使用新的配置完全覆盖现有的默认实例 (snell.service)！确定吗？" 12 60
                if [[ $? -ne 0 ]]; then return 1; fi
            fi
        else
            setup_paths "" # First install
        fi
        check_selinux
    fi

    # Load existing config if in modify mode
    local agent_name="MyNode${instance_suffix}"; local snell_port="36139"; local snell_mode="default"; local snell_ip_stack="ipv4";
    if [[ "$mode" == "modify" ]] && [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        load_manager_config "$SCRIPT_CONFIG_FILE"
        agent_name=$AGENT_NAME; snell_port=$SNELL_PORT; snell_mode=${SNELL_MODE:-default}; snell_ip_stack=${SNELL_IP_STACK:-ipv4};
    elif [[ -n "$instance_suffix" ]]; then # Suggest different ports for new coexisting instances
        local num=${instance_suffix#-}
        snell_port=$((36139 + num - 1))
    fi

    local form_items=("节点名称:" 1 1 "$agent_name" 1 28 40 0 "Snell 端口 (对外):" 2 1 "$snell_port" 2 28 40 0 "IP 栈 (ipv4/ipv6/ipv4+ipv6):" 3 1 "$snell_ip_stack" 3 28 40 0)
    local form_height=14
    local form_rows=5
    if [[ "$is_v6" == "true" ]]; then
        form_items+=("Snell v6 mode:" 4 1 "$snell_mode" 4 28 40 0)
        form_height=16
        form_rows=6
    fi

    local form_output; form_output=$(dialog --clear --backtitle "Snell 安装向导" --title "参数配置 (实例: ${SNELL_SERVICE_NAME})" --form "请输入以下参数:" "$form_height" 75 "$form_rows" "${form_items[@]}" 3>&1 1>&2 2>&3)
    if [[ -z "$form_output" ]]; then echo "取消操作。"; return 1; fi

    AGENT_NAME=$(echo "$form_output" | sed -n '1p')
    SNELL_PORT=$(echo "$form_output" | sed -n '2p')
    SNELL_IP_STACK=$(echo "$form_output" | sed -n '3p')
    SNELL_MODE=$(echo "$form_output" | sed -n '4p')
    SNELL_IP_STACK=${SNELL_IP_STACK:-ipv4}
    SNELL_MODE=${SNELL_MODE:-default}
    if ! validate_port "$SNELL_PORT"; then
        dialog --title "错误" --msgbox "Snell 端口必须是 1-65535 之间的数字。" 8 60
        return 1
    fi
    SNELL_PORT=$((10#$SNELL_PORT))
    if ! validate_ip_stack "$SNELL_IP_STACK"; then
        dialog --title "错误" --msgbox "IP 栈只能是: ipv4、ipv6、ipv4+ipv6。" 8 60
        return 1
    fi
    if [[ "$is_v6" == "true" && ! "$SNELL_MODE" =~ ^(default|unshaped|unsafe-raw)$ ]]; then
        dialog --title "错误" --msgbox "Snell v6 mode 只能是: default、unshaped、unsafe-raw。" 8 70
        return 1
    fi
    
    if [[ "$mode" == new && "${choice:-}" == coexist ]] &&
       [[ -e "$SNELL_SERVICE_FILE" || -e "$SNELL_CONFIG_DIR" || -e "${SNELL_INSTALL_DIR}/${SNELL_BINARY_NAME}" ]]; then
        echo "实例路径已被占用，取消共存安装，请重新选择。"
        return 1
    fi
    clear; echo "开始准备环境 (实例: ${SNELL_SERVICE_NAME})..."

    echo "正在下载 Snell Server (${install_version})..."
    if ! prepare_instance_change "$download_url"; then
        dialog --title "错误" --msgbox "Snell Server 下载、备份或替换失败！\n请检查网络、下载地址和文件权限。" 10 70
        return 1
    fi
    if ! mkdir -p "$SNELL_CONFIG_DIR"; then
        rollback_instance_change
        return 1
    fi
    echo -e "${Green}Snell Server 二进制文件 (${SNELL_BINARY_NAME}) 准备就绪。${NC}"

    echo "正在写入配置文件..."; local SNELL_PSK; local listen_address; local ipv6_enabled;
    if ! SNELL_PSK=$(openssl rand -base64 18) || [[ -z "$SNELL_PSK" ]]; then
        rollback_instance_change
        return 1
    fi
    listen_address=$(get_version_listen_value "$install_version" "$SNELL_PORT" "$SNELL_IP_STACK")
    ipv6_enabled=$(get_snell_ipv6_enabled "$SNELL_IP_STACK")
    
    cat > "$SNELL_CONFIG_FILE" << EOF || { rollback_instance_change; return 1; }
[snell-server]
listen = ${listen_address}
psk = ${SNELL_PSK}
ipv6 = ${ipv6_enabled}
EOF

    if snell_supports_custom_dns "$install_version"; then
        echo 'dns = 1.1.1.1, 9.9.9.9' >> "$SNELL_CONFIG_FILE" || { rollback_instance_change; return 1; }
    fi

    if [[ "$is_v6" == "true" ]]; then
        echo "mode = ${SNELL_MODE}" >> "$SNELL_CONFIG_FILE" || { rollback_instance_change; return 1; }
    fi

    local service_user_line="DynamicUser=yes"; local snell_user="snell${instance_suffix}"; if [[ -f /etc/os-release ]]; then source /etc/os-release; if [[ "$ID" == "centos" && "$VERSION_ID" == "7" ]]; then echo "检测到 CentOS 7，使用静态用户 '${snell_user}'。"; if ! id "${snell_user}" &>/dev/null; then useradd -r -s /bin/false "${snell_user}"; fi; service_user_line="User=${snell_user}"; fi; fi
    cat > "$SNELL_SERVICE_FILE" << EOF || { rollback_instance_change; return 1; }
[Unit]
Description=Snell Proxy Service (${SNELL_SERVICE_NAME})
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
Type=simple
${service_user_line}
LimitNOFILE=32768
ExecStart=${SNELL_INSTALL_DIR}/${SNELL_BINARY_NAME} -c ${SNELL_CONFIG_FILE}
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    
    cat > "$SCRIPT_CONFIG_FILE" << EOF || { rollback_instance_change; return 1; }
AGENT_NAME="${AGENT_NAME}"
SNELL_PORT="${SNELL_PORT}"
SNELL_PSK="${SNELL_PSK}"
SNELL_VERSION_INSTALLED="${install_version}"
IS_V3_SPECIAL=${special_flag}
SNELL_MODE="${SNELL_MODE}"
SNELL_IP_STACK="${SNELL_IP_STACK}"
INSTANCE_SUFFIX="${instance_suffix}"
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
    if ! systemctl daemon-reload; then
        rollback_instance_change
        return 1
    fi
    open_firewall_ports "$SNELL_PORT"
    if ! finish_instance_change; then
        press_any_key
        return 1
    fi
    systemctl enable "$SNELL_SERVICE_NAME" >/dev/null 2>&1
    clear
    echo -e "${Green}实例 ${SNELL_SERVICE_NAME} 安装/配置成功完成！${NC}"
    
    # 仅在全新安装时设置别名和报告
    if [[ "$mode" == "new" ]]; then
        setup_alias
    fi

    view_config current
}

do_install_latest() {
    local install_version; install_version=$(get_install_snell_version)
    local snell_url; snell_url=$(get_snell_download_url "$install_version") || return 1
    _install_or_modify_logic "$install_version" "$snell_url" "false" "new"
}

do_install_v6() {
    local install_version; install_version=$(get_install_snell_v6_version)
    local snell_url; snell_url=$(get_snell_download_url "$install_version") || return 1
    _install_or_modify_logic "$install_version" "$snell_url" "false" "new"
}

do_install_v3_special() {
    local snell_url; snell_url=$(get_snell_download_url v3.0.1) || return 1
    _install_or_modify_logic "v3.0.1" "$snell_url" "true" "new"
}

do_modify_config() {
    if ! select_snell_instance "修改配置"; then return; fi
    
    local current_version; local is_v3_special_flag;
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        load_manager_config "$SCRIPT_CONFIG_FILE"
        current_version="$SNELL_VERSION_INSTALLED"
        is_v3_special_flag="$IS_V3_SPECIAL"
    else
        dialog --title "错误" --msgbox "找不到此实例的管理配置文件 (${SCRIPT_CONFIG_FILE})。\n无法继续修改。" 10 70
        return
    fi

    local download_url;
    if [[ "$is_v3_special_flag" == "true" ]]; then
        current_version=v3.0.1
    fi
    download_url=$(get_snell_download_url "$current_version") || return 1
    
    _install_or_modify_logic "$current_version" "$download_url" "$is_v3_special_flag" "modify"
}

do_update_snell() {
    if ! select_snell_instance "更新 Snell 版本"; then return; fi
    
    local snell_version_installed;
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then load_manager_config "$SCRIPT_CONFIG_FILE"; else echo "配置缺失"; return; fi
    snell_version_installed="$SNELL_VERSION_INSTALLED"
    
    clear; echo -e "${Yellow}正在为实例 ${SNELL_SERVICE_NAME} 检查最新版本...${NC}"; local remote_version; remote_version=$(get_latest_snell_version)
    if [[ "$remote_version" == "error" || -z "$remote_version" ]]; then dialog --title "错误" --msgbox "获取远程版本信息失败！" 10 50; return; fi
    echo -e "当前已安装版本: ${Green}${snell_version_installed}${NC}"; echo -e "远程最新版本:   ${Green}${remote_version}${NC}"
    if [[ "$snell_version_installed" == "$remote_version" ]]; then dialog --title "提示" --msgbox "恭喜！此实例已是最新版本。" 8 50; return; fi
    
    dialog --title "发现新版本" --yesno "发现新版本 ${remote_version}。\n是否要为实例 ${SNELL_SERVICE_NAME} 更新？" 10 60
    if [[ $? -ne 0 ]]; then return; fi
    
    clear; echo "准备更新..."
    local NEW_SNELL_URL; NEW_SNELL_URL=$(get_snell_download_url "$remote_version") || return 1
    if ! prepare_instance_change "$NEW_SNELL_URL"; then
        echo "下载、备份或替换失败"; press_any_key; return 1
    fi
    if ! migrate_version_config "$remote_version"; then
        echo "配置迁移失败"
        rollback_instance_change
        press_any_key; return 1
    fi
    if ! finish_instance_change; then press_any_key; return 1; fi
    echo -e "${Green}实例 ${SNELL_SERVICE_NAME} 已成功更新至 ${remote_version}！${NC}"; press_any_key
}

do_rollback_snell() {
    local install_mode=new snell_version_installed="未安装" existing_service
    existing_service=$(find /etc/systemd/system/ -maxdepth 1 -name 'snell*.service' -print -quit 2>/dev/null)
    if [[ -n "$existing_service" ]]; then
        if ! select_snell_instance "更换 Snell 版本"; then return; fi
        if ! load_manager_config "$SCRIPT_CONFIG_FILE"; then echo "配置缺失"; return 1; fi
        install_mode=modify
        snell_version_installed="$SNELL_VERSION_INSTALLED"
    fi

    clear; echo "获取可用版本..."; local available_versions; available_versions=$(get_available_versions)
    if [[ "$available_versions" == "error" || -z "$available_versions" ]]; then dialog --title "错误" --msgbox "获取版本列表失败！" 10 50; return; fi
    
    local menu_items=() version note
    while IFS= read -r version; do
        validate_snell_version "$version" || continue
        note=$(get_version_install_note "$version")
        if [[ "$version" == "$snell_version_installed" || ( "$version" == v3.0.1 && "${IS_V3_SPECIAL:-}" == true && "$install_mode" == modify ) ]]; then
            note="[当前版本，可重装] $note"
        fi
        menu_items+=("$version" "$note")
    done <<< "$available_versions"
    if [[ ${#menu_items[@]} -eq 0 ]]; then echo "没有可选择的版本。"; return 1; fi
    
    local selected_version
    selected_version=$(dialog --clear --title "选择 Snell 版本" --menu "当前版本: ${snell_version_installed}\n官方发布版本及仓库兼容版（旧版双栈依赖系统 IPv6 socket 兼容）:" 0 0 0 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then return; fi
    if ! validate_snell_version "$selected_version" || ! grep -Fxq "$selected_version" <<< "$available_versions"; then
        echo "无效的版本选择。"; return 1
    fi
    local ROLLBACK_URL special_flag=false
    ROLLBACK_URL=$(get_snell_download_url "$selected_version") || { press_any_key; return 1; }
    [[ "$selected_version" != v3.0.1 ]] || special_flag=true
    if [[ "$install_mode" == new ]]; then
        _install_or_modify_logic "$selected_version" "$ROLLBACK_URL" "$special_flag" new
        return $?
    fi

    note=$(get_version_install_note "$selected_version")
    dialog --title "确认更换" --yesno "将实例 ${SNELL_SERVICE_NAME} 更换到 ${selected_version}？\n\n${note}\n下载包: ${ROLLBACK_URL}\n\n保留端口和 PSK，按目标版本迁移配置。更换后请更新客户端 version/mode。" 0 0
    if [[ $? -ne 0 ]]; then return; fi

    clear; echo "准备更换..."
    if ! prepare_instance_change "$ROLLBACK_URL"; then
        echo "下载、备份或替换失败"; press_any_key; return 1
    fi
    if ! migrate_version_config "$selected_version"; then
        echo "配置迁移失败"
        rollback_instance_change
        press_any_key; return 1
    fi
    if [[ "$selected_version" == v5* ]]; then open_firewall_ports "$SNELL_PORT"; fi
    if ! finish_instance_change; then press_any_key; return 1; fi
    echo -e "${Green}实例 ${SNELL_SERVICE_NAME} 已成功更换至 ${selected_version}！${NC}"
    view_config current
}

do_uninstall_menu() {
    if ! select_snell_instance "卸载 Snell 实例"; then return; fi

    dialog --title "确认卸载" --yesno "【警告】\n确定要永久卸载实例 ${SNELL_SERVICE_NAME} 吗？\n\n这将删除此实例所有相关文件和配置！此操作不可逆！" 12 60
    if [[ $? -ne 0 ]]; then return; fi
    
    _perform_uninstall
}

_perform_uninstall() {
    if ! is_safe_instance_path "$SNELL_CONFIG_DIR"; then
        echo -e "${Red}检测到异常配置目录，已取消卸载: ${SNELL_CONFIG_DIR}${NC}"
        press_any_key
        return 1
    fi

    clear; echo "正在卸载实例 ${SNELL_SERVICE_NAME}..."
    echo "--> 停止并禁用服务..."
    systemctl stop "$SNELL_SERVICE_NAME" >/dev/null 2>&1
    systemctl disable "$SNELL_SERVICE_NAME" >/dev/null 2>&1
    
    echo "--> 删除二进制文件..."
    rm -f "${SNELL_INSTALL_DIR}/${SNELL_BINARY_NAME}"
    
    echo "--> 删除配置文件和目录..."
    rm -rf "$SNELL_CONFIG_DIR"
    
    echo "--> 删除服务单元文件..."
    rm -f "$SNELL_SERVICE_FILE"
    
    echo "--> 重新加载 systemd..."
    systemctl daemon-reload

    if [[ -z $(find /etc/systemd/system/ -maxdepth 1 -name "snell*.service" -print -quit 2>/dev/null) ]]; then
        echo "--> 未检测到其他 Snell 实例，清理内核调优配置..."
        sed -i -e '/# Kernel network tuning by Snell manager script/,+4d' /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
    
    echo -e "\n${Green}实例 ${SNELL_SERVICE_NAME} 已成功卸载！${NC}"
    press_any_key
}

do_start() {
    if ! select_snell_instance "启动 Snell 服务"; then return; fi
    local is_running;
    if systemctl is-active --quiet "$SNELL_SERVICE_NAME"; then is_running=true; else is_running=false; fi
    if $is_running; then dialog --title "提示" --msgbox "实例 ${SNELL_SERVICE_NAME} 已在运行中。" 8 50; return; fi
    
    echo "正在启动服务..."; systemctl start "$SNELL_SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SNELL_SERVICE_NAME"; then echo -e "${Green}启动成功！${NC}"; else echo -e "${Red}启动失败。${NC}"; fi
    press_any_key
}

do_stop() {
    if ! select_snell_instance "停止 Snell 服务"; then return; fi
    local is_running;
    if systemctl is-active --quiet "$SNELL_SERVICE_NAME"; then is_running=true; else is_running=false; fi
    if ! $is_running; then dialog --title "提示" --msgbox "实例 ${SNELL_SERVICE_NAME} 未运行。" 8 50; return; fi

    echo "正在停止服务..."; systemctl stop "$SNELL_SERVICE_NAME" >/dev/null 2>&1
    sleep 1; echo -e "${Green}服务已停止。${NC}"; press_any_key
}

do_restart() {
    [[ -n "$SNELL_SERVICE_NAME" ]] || return 1
    echo "正在重启服务 ${SNELL_SERVICE_NAME}..."
    if ! systemctl restart "$SNELL_SERVICE_NAME"; then
        echo -e "${Red}重启失败。${NC}"
        return 1
    fi
    sleep 1
    if systemctl is-active --quiet "$SNELL_SERVICE_NAME"; then
        echo -e "${Green}重启成功！${NC}"
        return 0
    fi
    echo -e "${Red}重启失败。${NC}"
    return 1
}

view_config() {
    if [[ "${1:-}" != current ]] && ! select_snell_instance "查看配置信息"; then return 1; fi

    if [[ ! -f "$SCRIPT_CONFIG_FILE" ]]; then
        dialog --title "错误" --msgbox "找不到实例 ${SNELL_SERVICE_NAME} 的管理配置文件。" 8 60
        return
    fi
    load_manager_config "$SCRIPT_CONFIG_FILE"

    local snell_major_version
    if [[ "$IS_V3_SPECIAL" == "true" ]]; then
        snell_major_version="3"
    else
        local temp_version=${SNELL_VERSION_INSTALLED#v}
        snell_major_version=${temp_version%%.*}
    fi
    
    local ip_stack public_ipv4 public_ipv6 public_ipv6_raw proxy_host final_config_string; ip_stack=${SNELL_IP_STACK:-ipv4}
    if [[ "$ip_stack" == "ipv4" || "$ip_stack" == "ipv4+ipv6" ]]; then
        public_ipv4=$(curl -s4 --connect-timeout 5 --max-time 10 ifconfig.me)
        if [[ -z "$public_ipv4" ]]; then
            public_ipv4="YOUR_SERVER_IP"
            echo -e "${Yellow}无法自动获取公网 IPv4，客户端配置中将使用占位地址 YOUR_SERVER_IP。${NC}"
            sleep 1
        fi
    fi
    if [[ "$ip_stack" == "ipv6" || "$ip_stack" == "ipv4+ipv6" ]]; then
        public_ipv6=$(curl -s6 --connect-timeout 5 --max-time 10 ifconfig.me)
        if [[ -n "$public_ipv6" ]]; then
            public_ipv6_raw="$public_ipv6"
            public_ipv6="[${public_ipv6}]"
        else
            public_ipv6_raw="YOUR_SERVER_IPV6"
            public_ipv6="[YOUR_SERVER_IPV6]"
            echo -e "${Yellow}无法自动获取公网 IPv6，客户端配置中将使用占位地址 [YOUR_SERVER_IPV6]。${NC}"
            sleep 1
        fi
    fi

    case "$ip_stack" in
        ipv6)
            proxy_host="$public_ipv6"
            ;;
        ipv4+ipv6)
            proxy_host="YOUR_SERVER_DOMAIN"
            ;;
        *)
            proxy_host="$public_ipv4"
            ;;
    esac

    final_config_string="${AGENT_NAME} = snell, ${proxy_host}, ${SNELL_PORT}, psk=${SNELL_PSK}, version=${snell_major_version}, reuse=true, tfo=true, ecn=true"
    if [[ "$ip_stack" == "ipv4+ipv6" ]]; then
        echo -e "${Yellow}IPv4+IPv6 单节点需要使用同时解析到 A 和 AAAA 记录的域名，请将 YOUR_SERVER_DOMAIN 替换为您的域名。${NC}"
        sleep 1
    fi
    if [[ "$snell_major_version" == "6" ]]; then
        final_config_string="${final_config_string}, mode=${SNELL_MODE:-default}"
    fi
    
    dialog --title "客户端配置 (${SNELL_SERVICE_NAME})" --msgbox "关闭此窗口后，配置将打印在终端。" 8 70
    
    clear
    echo -e "${Green}================== 实例 ${SNELL_SERVICE_NAME} 配置 ==================${NC}"
    echo -e "${Yellow}请复制以下完整的客户端配置信息：${NC}\n"
    echo "${final_config_string}"
    if [[ "$ip_stack" == "ipv4+ipv6" ]]; then
        echo -e "\n${Yellow}双栈 DNS 记录建议：${NC}"
        echo "A    YOUR_SERVER_DOMAIN -> ${public_ipv4}"
        echo "AAAA YOUR_SERVER_DOMAIN -> ${public_ipv6_raw}"
    fi
    echo -e "\n${Green}==================================================================${NC}"
    press_any_key
}

view_log() {
    if ! select_snell_instance "查看运行日志"; then return; fi
    clear; echo -e "加载 Snell 日志... ${Yellow}(按 'q' 键退出)${NC}"; sleep 1; journalctl -e -u "$SNELL_SERVICE_NAME" -f
}

get_latest_script_url() {
    local metadata revision
    metadata=$(curl -fsSL --connect-timeout 10 --max-time 30 \
        -H 'Cache-Control: no-cache' \
        "${SCRIPT_REF_API_URL}?check=$(date +%s)") || return 1
    revision=$(printf '%s\n' "$metadata" | sed -n 's/^[[:space:]]*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' | head -n 1)
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf '%s/%s/snell-ai.sh\n' "${SCRIPT_URL%/main/snell-ai.sh}" "$revision"
}

update_script() {
    clear; echo "正在检查更新..."
    local script_path update_url temp_script remote_version latest_version
    script_path=$(realpath "$0") || return 1
    if ! update_url=$(get_latest_script_url); then
        echo -e "${Red}无法获取最新提交信息，请稍后重试。${NC}"
        press_any_key; return 1
    fi
    # 使用固定提交地址只下载一次，版本检查与实际安装使用同一份内容。
    temp_script=$(mktemp "${script_path}.update.XXXXXX") || return 1
    if ! curl -fsSL --connect-timeout 10 --max-time 30 "$update_url" -o "$temp_script"; then
        echo -e "${Red}下载新脚本失败！${NC}"
        rm -f "$temp_script"; press_any_key; return 1
    fi
    remote_version=$(sed -n 's/^SCRIPT_VERSION="\([0-9][0-9.]*\)"$/\1/p' "$temp_script" | head -n 1)
    if [[ ! "$remote_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
       ! grep -q '^main "\$@"' "$temp_script" || ! bash -n "$temp_script"; then
        echo -e "${Red}下载的新脚本内容校验失败，已取消更新。${NC}"
        rm -f "$temp_script"; press_any_key; return 1
    fi
    latest_version=$(printf '%s\n%s\n' "$SCRIPT_VERSION" "$remote_version" | sort -V | tail -n 1)
    if [[ "$latest_version" == "$SCRIPT_VERSION" ]]; then
        rm -f "$temp_script"
        echo -e "${Green}当前已是最新版本 (${SCRIPT_VERSION})。${NC}"
        press_any_key; return 0
    fi
    if ! chmod --reference="$script_path" "$temp_script" || ! chmod u+x "$temp_script" ||
       ! mv "$temp_script" "$script_path"; then
        echo -e "${Red}替换脚本失败，原脚本未更新。${NC}"
        rm -f "$temp_script"; press_any_key; return 1
    fi
    echo -e "${Green}脚本已更新至 ${remote_version}！正在重新运行...${NC}"
    sleep 2; cleanup_ui
    exec "$script_path"
}

show_menu() {
    printf '%b' "$NC"
    clear
    local instance_count=0 active_count=0 service_name services arch terminal_rows=32
    if [[ -t 1 ]]; then terminal_rows=$(tput lines 2>/dev/null) || terminal_rows=24; fi
    services=$(find /etc/systemd/system/ -maxdepth 1 -name "snell*.service" -exec basename {} \; 2>/dev/null | sort -V)
    while IFS= read -r service_name; do
        [[ -n "$service_name" ]] || continue
        instance_count=$((instance_count + 1))
        if systemctl is-active --quiet "$service_name"; then active_count=$((active_count + 1)); fi
    done <<< "$services"
    if [[ -z "$latest_snell_version_cache" || -z "$latest_snell_v6_version_cache" ]]; then
        echo -e "${Dim}[*] 正在同步官方发布版本...${NC}"
        latest_snell_version_cache=$(get_install_snell_version)
        latest_snell_v6_version_cache=$(get_install_snell_v6_version)
        clear
    fi
    arch=$(get_linux_arch 2>/dev/null) || arch=unknown
    if [[ -t 1 ]]; then printf '\033[0;32;40m'; fi
    printf '%b' "$Green"
    if ((terminal_rows >= 30)); then
    cat <<'EOF'
     _____ _   _ ______ _      _
    / ____| \ | |  ____| |    | |
   | (___ |  \| | |__  | |    | |
    \___ \| . ` |  __| | |    | |
    ____) | |\  | |____| |____| |____
   |_____/|_| \_|______|______|______|
EOF
    else
        printf '   [ S N E L L ]  //  SERVER CONTROL\n'
    fi
    echo -e "${Dim}   S E R V E R   /   C O N T R O L   C O N S O L E${NC}"
    echo -e "${Dim}   ----------------------------------------------------------${NC}"
    echo -e "   ${Cyan}SYSTEM${NC} v${SCRIPT_VERSION}  ${Dim}//${NC} ${arch}  ${Dim}//${NC} ${Green}${active_count} ONLINE${NC} / ${instance_count} INSTANCES"
    echo -e "   ${Dim}SESSION${NC} 本日 ${today_usage_count} 次  ${Dim}//${NC} 累计 ${total_usage_count} 次"
    echo
    echo -e "   ${Dim}[ 01 / DEPLOY ]${NC}"
    echo -e "   ${Green}[1]${NC} 安装 Snell ${Cyan}${latest_snell_version_cache}${NC}    ${Green}[2]${NC} 安装 v6 ${Cyan}${latest_snell_v6_version_cache}${NC}"
    echo -e "   ${Green}[3]${NC} 安装 v3.0.1 兼容版       ${Green}[5]${NC} 选择版本安装 / 更换版本"
    echo -e "   ${Green}[4]${NC} 更新实例版本              ${Green}[0]${NC} 更新管理脚本"
    echo
    echo -e "   ${Dim}[ 02 / OPERATE ]${NC}"
    echo -e "   ${Green}[7]${NC} 启动实例   ${Yellow}[8]${NC} 停止实例   ${Cyan}[9]${NC} 重启实例"
    echo -e "   ${Green}[10]${NC} 修改配置  ${Green}[11]${NC} 查看配置  ${Green}[12]${NC} 运行日志"
    echo
    echo -e "   ${Dim}[ 03 / CONTROL ]${NC}"
    echo -e "   ${Red}[6]${NC} 卸载实例                  ${Green}[00]${NC} 退出控制台"
    echo -e "${Dim}   ----------------------------------------------------------${NC}"
    echo -e "   ${Dim}READY${NC} ${Green}输入操作编号后按 Enter${NC}\n"
}

main() {
    check_root
    report_first_run
    install_dependencies
    setup_ui
    update_usage_stats
    while true; do
        show_menu
        printf '%b' "${Green}   root@snell${NC}:${Cyan}~${NC}# "
        read -r choice || return 0
        case "$choice" in
            0) update_script ;; 
            1) do_install_latest ;; 
            2) do_install_v6 ;;
            3) do_install_v3_special ;;
            4) do_update_snell ;;
            5) do_rollback_snell ;;
            6) do_uninstall_menu ;;
            7) do_start ;;
            8) do_stop ;;
            9) if select_snell_instance "重启 Snell 服务"; then do_restart; press_any_key; fi ;;
            10) do_modify_config ;;
            11) view_config ;;
            12) view_log ;;
            00) exit 0 ;;
            *) echo -e "${Red}无效输入。${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
