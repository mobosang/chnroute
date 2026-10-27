#!/bin/bash

# ==============================================================================
# Snell Server 全功能管理脚本 (定制版-GOOGLE AI 生成)
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
SCRIPT_VERSION="3.5.8"
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
SNELL_V3_SPECIAL_URL="https://raw.githubusercontent.com/mobosang/chnroute/main/snell-server-v3.0.1-linux-amd64.zip"
SNELL_V6_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_V6_VERSION_FOR_INSTALL}-linux-amd64.zip"
# 【【【 重要配置 】】】 请将下面的 URL 替换为您自己的服务器端点
COUNTER_ENDPOINT_URL="http://your-server-domain.com/counter.php"


# --- 颜色定义 ---
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
NC="\033[0m"

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

get_snell_extra_listen_address() {
    local ip_stack="$1"
    case "$ip_stack" in
        ipv4+ipv6) echo "[::]" ;;
        *) echo "" ;;
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
        ! chmod +x "$CHANGE_DIR/new-binary"; then
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

migrate_version_config() {
    local target_version="$1" effective_mode listen_address
    validate_port "$SNELL_PORT" || return 1
    local port=$((10#$SNELL_PORT)) ip_stack=${SNELL_IP_STACK:-ipv4}
    validate_ip_stack "$ip_stack" || return 1
    listen_address="$(get_snell_listen_address "$ip_stack"):$port"
    if [[ "$target_version" == v6* && "$ip_stack" == ipv4+ipv6 ]]; then
        listen_address="0.0.0.0:$port, [::]:$port"
    fi
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
    fi
    sed -i '/^SNELL_MODE=/d' "$SCRIPT_CONFIG_FILE" || return 1
    echo "SNELL_MODE=\"$effective_mode\"" >> "$SCRIPT_CONFIG_FILE" || return 1
    sed -i -e "s/^SNELL_VERSION_INSTALLED=.*/SNELL_VERSION_INSTALLED=\"${target_version}\"/" \
        -e 's/^IS_V3_SPECIAL=.*/IS_V3_SPECIAL=false/' "$SCRIPT_CONFIG_FILE"
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

get_available_versions() {
    local versions; versions=$(curl -sL --connect-timeout 10 "$SNELL_RELEASE_NOTES_URL" | grep -oP '(?<=snell-server-)v[^-]+' | sort -urV)
    if [[ -z "$versions" ]]; then echo "error"; else echo "$versions"; fi
}

_install_or_modify_logic() {
    local install_version="$1"
    local download_url="$2"
    local special_flag="$3" # true or false for v3
    local mode="$4" # "new" or "modify"
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

    echo "正在写入配置文件..."; local SNELL_PSK; local listen_address; local extra_listen_address; local ipv6_enabled;
    if ! SNELL_PSK=$(openssl rand -base64 18) || [[ -z "$SNELL_PSK" ]]; then
        rollback_instance_change
        return 1
    fi
    listen_address=$(get_snell_listen_address "$SNELL_IP_STACK")
    extra_listen_address=$(get_snell_extra_listen_address "$SNELL_IP_STACK")
    ipv6_enabled=$(get_snell_ipv6_enabled "$SNELL_IP_STACK")
    if [[ "$is_v6" == "true" && "$SNELL_IP_STACK" == "ipv4+ipv6" ]]; then
        listen_address="0.0.0.0"
    fi
    
    cat > "$SNELL_CONFIG_FILE" << EOF || { rollback_instance_change; return 1; }
[snell-server]
dns = 1.1.1.1, 9.9.9.9
psk = ${SNELL_PSK}
ipv6 = ${ipv6_enabled}
EOF

    if [[ "$is_v6" == "true" && -n "$extra_listen_address" ]]; then
        sed -i "/^dns = /a listen = ${listen_address}:${SNELL_PORT}, ${extra_listen_address}:${SNELL_PORT}" "$SNELL_CONFIG_FILE" || { rollback_instance_change; return 1; }
    else
        sed -i "/^dns = /a listen = ${listen_address}:${SNELL_PORT}" "$SNELL_CONFIG_FILE" || { rollback_instance_change; return 1; }
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
    local snell_url="https://dl.nssurge.com/snell/snell-server-${install_version}-linux-amd64.zip"
    _install_or_modify_logic "$install_version" "$snell_url" "false" "new"
}

do_install_v6() {
    local install_version; install_version=$(get_install_snell_v6_version)
    local snell_url="https://dl.nssurge.com/snell/snell-server-${install_version}-linux-amd64.zip"
    _install_or_modify_logic "$install_version" "$snell_url" "false" "new"
}

do_install_v3_special() {
    _install_or_modify_logic "v3.0.1 (兼容版)" "$SNELL_V3_SPECIAL_URL" "true" "new"
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
        download_url="$SNELL_V3_SPECIAL_URL"
    else
        download_url="https://dl.nssurge.com/snell/snell-server-${current_version}-linux-amd64.zip"
    fi
    
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
    local NEW_SNELL_URL="https://dl.nssurge.com/snell/snell-server-${remote_version}-linux-amd64.zip"
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
    if ! select_snell_instance "更换 Snell 版本"; then return; fi
    
    local snell_version_installed;
    if [[ -f "$SCRIPT_CONFIG_FILE" ]]; then load_manager_config "$SCRIPT_CONFIG_FILE"; else echo "配置缺失"; return; fi
    snell_version_installed="$SNELL_VERSION_INSTALLED"

    clear; echo "获取可用版本..."; local available_versions; available_versions=$(get_available_versions)
    if [[ "$available_versions" == "error" || -z "$available_versions" ]]; then dialog --title "错误" --msgbox "获取版本列表失败！" 10 50; return; fi
    
    local rollback_options; rollback_options=$(echo "$available_versions" | grep -v "^${snell_version_installed}$")
    local menu_items=(); local count=1; while IFS= read -r version; do menu_items+=("$count" "$version"); ((count++)); done <<< "$rollback_options"
    
    local choice; choice=$(dialog --clear --menu "当前版本为 ${snell_version_installed}。\n请选择目标版本:" 20 60 15 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then return; fi
    
    local selected_version; selected_version=$(echo "$rollback_options" | sed -n "${choice}p")
    dialog --title "确认更换" --yesno "确定要将实例 ${SNELL_SERVICE_NAME} 更换到 ${selected_version} 吗？" 10 60
    if [[ $? -ne 0 ]]; then return; fi

    clear; echo "准备更换..."
    local ROLLBACK_URL="https://dl.nssurge.com/snell/snell-server-${selected_version}-linux-amd64.zip"
    if ! prepare_instance_change "$ROLLBACK_URL"; then
        echo "下载、备份或替换失败"; press_any_key; return 1
    fi
    if ! migrate_version_config "$selected_version"; then
        echo "配置迁移失败"
        rollback_instance_change
        press_any_key; return 1
    fi
    if ! finish_instance_change; then press_any_key; return 1; fi
    echo -e "${Green}实例 ${SNELL_SERVICE_NAME} 已成功更换至 ${selected_version}！${NC}"; press_any_key
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

update_script() {
    clear; echo "正在检查更新..."; local local_version=$SCRIPT_VERSION
    local remote_version; remote_version=$(curl -fsSL --connect-timeout 10 --max-time 30 "${SCRIPT_URL}" | grep 'SCRIPT_VERSION=' | head -n 1 | awk -F'"' '{print $2}')
    if [[ -z "$remote_version" ]]; then echo -e "${Red}获取远程版本信息失败。${NC}"; press_any_key; return; fi
    local latest_version; latest_version=$(printf "%s\n%s" "$local_version" "$remote_version" | sort -V | tail -n 1)
    if [[ "$latest_version" == "$local_version" ]]; then echo -e "${Green}恭喜！当前已是最新版本 (${local_version})。${NC}"; else
        echo -e "${Yellow}发现新版本: ${remote_version}，正在更新...${NC}"; local script_path="$0"; local temp_script; temp_script=$(mktemp)
        if ! curl -fsSL --connect-timeout 10 --max-time 30 "${SCRIPT_URL}" -o "$temp_script"; then echo -e "${Red}下载新脚本失败！${NC}"; rm -f "$temp_script"; press_any_key; return; fi
        if ! grep -q '^SCRIPT_VERSION=' "$temp_script" || ! grep -q '^main "\$@"' "$temp_script"; then echo -e "${Red}下载的新脚本内容校验失败，已取消更新。${NC}"; rm -f "$temp_script"; press_any_key; return; fi
        mv "$temp_script" "${script_path}"
        chmod +x "${script_path}"; echo -e "${Green}脚本已更新至 ${remote_version}！正在重新运行...${NC}"; sleep 2; exec "${script_path}"
    fi; press_any_key
}

show_menu() {
    clear
    local instance_count install_version install_v6_version
    instance_count=$(find /etc/systemd/system/ -maxdepth 1 -name "snell*.service" 2>/dev/null | wc -l)
    install_version=$(get_install_snell_version)
    install_v6_version=$(get_install_snell_v6_version)

    echo -e "Snell Server 多实例管理脚本 (纯净版) [v${SCRIPT_VERSION}]"; echo -e "================================================="
    echo -e "${Green}0.${NC} 更新脚本"
    echo -e "-------------------------------------------------"
    echo -e "${Green}1.${NC} 安装 Snell Server (${install_version})"
    echo -e "${Green}2.${NC} 安装 Snell v6 (${install_v6_version})"
    echo -e "${Yellow}3.${NC} 安装 Snell v3.0.1 (兼容版)"
    echo -e "-------------------------------------------------"
    echo -e "${Yellow}4.${NC} 更新一个实例的版本"
    echo -e "${Yellow}5.${NC} 更换一个实例的版本"
    echo -e "${Red}6.${NC} 卸载一个 Snell 实例"
    echo -e "-------------------------------------------------"
    echo -e "${Green}7.${NC} 启动一个实例"
    echo -e "${Green}8.${NC} 停止一个实例"
    echo -e "${Green}9.${NC} 重启一个实例"
    echo -e "-------------------------------------------------"
    echo -e "${Green}10.${NC} 修改一个实例的配置"
    echo -e "${Green}11.${NC} 查看一个实例的配置"
    echo -e "${Green}12.${NC} 查看一个实例的日志"
    echo -e "-------------------------------------------------"
    echo -e "${Green}00.${NC} 退出脚本"
    echo -e "================================================="
    echo -e "当前已安装实例数量: ${Green}${instance_count}${NC}"
    echo -e "总计使用: ${Yellow}${total_usage_count}${NC} 次 | 本日使用: ${Yellow}${today_usage_count}${NC} 次"
    echo -e "请选择一个操作...\n"
}

main() {
    check_root
    report_first_run
    install_dependencies
    update_usage_stats
    while true; do
        show_menu
        read -r -p "请输入操作编号 [0-12，00 退出]: " choice || return 0
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
