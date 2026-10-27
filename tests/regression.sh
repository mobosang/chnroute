#!/bin/bash
# 在临时目录中验证；不下载、不操作真实服务或 /etc 配置。
set -e
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/snell-ai.sh"
source <(sed '$d' "$root/snell-ai.sh")
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
clear() { :; }
sleep() { :; }
press_any_key() { :; }
check_selinux() { :; }
select_snell_instance() { return 0; }
get_latest_snell_version() { echo v6.0.0; }
get_available_versions() { printf 'v6.0.0rc\nv5.0.1\n'; }
dialog() { case " $* " in *' --menu '*) printf 1 >&2 ;; esac; return 0; }
download_snell_binary() {
    [[ "${fail_download:-false}" != true ]] || return 1
    printf 'new-binary\n' > "$2"
}
systemctl() {
    printf '%s\n' "$*" >> "$test_dir/actions"
    case "$1" in
        is-active) [[ $(cat "$test_dir/state") == running ]] ;;
        stop) echo stopped > "$test_dir/state" ;;
        start) echo running > "$test_dir/state" ;;
        restart)
            if [[ "${fail_restart:-false}" == true ]]; then
                echo stopped > "$test_dir/state"
                return 1
            fi
            echo running > "$test_dir/state"
            ;;
    esac
}
fixture() {
    SNELL_INSTALL_DIR="$test_dir/bin"
    SNELL_CONFIG_DIR="$test_dir/config"
    SNELL_CONFIG_FILE="$SNELL_CONFIG_DIR/server.conf"
    SCRIPT_CONFIG_FILE="$SNELL_CONFIG_DIR/manager.conf"
    SNELL_SERVICE_FILE="$test_dir/unit.service"
    SNELL_SERVICE_NAME=snell.service
    SNELL_BINARY_NAME=snell-server
    mkdir -p "$SNELL_INSTALL_DIR" "$SNELL_CONFIG_DIR"
    printf 'old-binary\n' > "$SNELL_INSTALL_DIR/$SNELL_BINARY_NAME"
    printf 'old-unit\n' > "$SNELL_SERVICE_FILE"
    cat > "$SCRIPT_CONFIG_FILE" <<'EOF'
SNELL_VERSION_INSTALLED="v6.0.0rc"
IS_V3_SPECIAL=false
SNELL_MODE="unshaped"
SNELL_PORT="36139"
SNELL_IP_STACK="ipv4+ipv6"
EOF
    cat > "$SNELL_CONFIG_FILE" <<'EOF'
[snell-server]
mode = unshaped
listen = 0.0.0.0:36139, [::]:36139
ipv6 = true
EOF
    cp "$SCRIPT_CONFIG_FILE" "$test_dir/original-manager"
    cp "$SNELL_CONFIG_FILE" "$test_dir/original-server"
    echo running > "$test_dir/state"
    : > "$test_dir/actions"
    fail_download=false
    fail_restart=false
}
assert_original() {
    cmp "$SCRIPT_CONFIG_FILE" "$test_dir/original-manager"
    cmp "$SNELL_CONFIG_FILE" "$test_dir/original-server"
    [[ $(cat "$SNELL_INSTALL_DIR/$SNELL_BINARY_NAME") == old-binary ]]
    [[ $(cat "$SNELL_SERVICE_FILE") == old-unit ]]
}
test_ports() {
    local port
    for port in 1 80 0080 65535; do validate_port "$port" || return 1; done
    for port in 0 00000 65536 99999999999999999999 -1 '80x' ''; do
        if validate_port "$port"; then return 1; fi
    done
}
test_collision() (
    find() { printf 'snell.service\nsnell-3.service\n'; }
    dialog() {
        case " $* " in
            *' --menu '*) printf coexist >&2 ;;
            *' --form '*) return 1 ;;
        esac
        return 0
    }
    if _install_or_modify_logic v6.0.0 ignored false new; then return 1; fi
    [[ "$SNELL_SERVICE_NAME" == snell-2.service ]]
)
test_download_failure() {
    fixture
    fail_download=true
    if do_update_snell; then return 1; fi
    assert_original
    [[ $(cat "$test_dir/state") == running ]]
    ! grep -q '^stop ' "$test_dir/actions"
}
test_mode() {
    fixture
    do_update_snell
    grep -qx 'SNELL_MODE="unshaped"' "$SCRIPT_CONFIG_FILE"
    grep -qx 'mode = unshaped' "$SNELL_CONFIG_FILE"
    grep -qx 'SNELL_VERSION_INSTALLED="v6.0.0"' "$SCRIPT_CONFIG_FILE"
    [[ $(cat "$SNELL_INSTALL_DIR/$SNELL_BINARY_NAME") == new-binary ]]
    [[ $(cat "$test_dir/state") == running ]]
    [[ ! -d "$CHANGE_DIR" ]]
}
test_restart_failure() {
    fixture
    fail_restart=true
    if do_update_snell > "$test_dir/output"; then return 1; fi
    assert_original
    [[ $(cat "$test_dir/state") == running ]]
    ! grep -q '已成功更新' "$test_dir/output"
}
test_inactive_recovery() {
    fixture
    echo stopped > "$test_dir/state"
    fail_restart=true
    if do_update_snell; then return 1; fi
    assert_original
    [[ $(cat "$test_dir/state") == stopped ]]
    ! grep -q '^start ' "$test_dir/actions"
}
test_downgrade() {
    fixture
    do_rollback_snell
    grep -qx 'listen = \[::\]:36139' "$SNELL_CONFIG_FILE"
    grep -qx 'SNELL_VERSION_INSTALLED="v5.0.1"' "$SCRIPT_CONFIG_FILE"
    ! grep -q '^mode = ' "$SNELL_CONFIG_FILE"
    grep -qx 'SNELL_MODE="default"' "$SCRIPT_CONFIG_FILE"
}
test_migration_failure() {
    fixture
    sed -i 's/SNELL_PORT="36139"/SNELL_PORT="invalid"/' "$SCRIPT_CONFIG_FILE"
    cp "$SCRIPT_CONFIG_FILE" "$test_dir/original-manager"
    if do_update_snell; then return 1; fi
    assert_original
    [[ $(cat "$test_dir/state") == running ]]
}
test_upgrade_from_v5() {
    fixture
    sed -i 's/v6.0.0rc/v5.0.1/' "$SCRIPT_CONFIG_FILE"
    sed -i '/^mode = /d; s/^listen = .*/listen = [::]:36139/' "$SNELL_CONFIG_FILE"
    do_update_snell
    grep -qx 'mode = default' "$SNELL_CONFIG_FILE"
    grep -qx 'SNELL_MODE="default"' "$SCRIPT_CONFIG_FILE"
    grep -Fxq 'listen = 0.0.0.0:36139, [::]:36139' "$SNELL_CONFIG_FILE"
}
test_recovery_failure_retains_backup() (
    fixture
    load_manager_config
    prepare_instance_change ignored
    systemctl() { return 1; }
    if rollback_instance_change; then return 1; fi
    [[ -f "$CHANGE_DIR/backup-0" ]]
    [[ $(cat "$CHANGE_DIR/backup-0") == old-binary ]]
)
test_view_selection() (
    select_snell_instance() { echo selected > "$test_dir/selected-view"; return 1; }
    SNELL_SERVICE_NAME=snell-3.service
    if view_config; then return 1; fi
    [[ -f "$test_dir/selected-view" ]]
)
test_menu() (
    check_root() { :; }
    report_first_run() { :; }
    install_dependencies() { :; }
    update_usage_stats() { :; }
    show_menu() { :; }
    SNELL_SERVICE_NAME=snell-3.service
    select_snell_instance() { echo selected > "$test_dir/selected-restart"; SNELL_SERVICE_NAME=snell-2.service; }
    do_restart() { echo "$SNELL_SERVICE_NAME" > "$test_dir/restarted"; }
    main <<< $'9\n00'
)
for test in test_ports test_collision test_download_failure test_mode test_restart_failure test_inactive_recovery test_downgrade test_migration_failure test_upgrade_from_v5 test_recovery_failure_retains_backup test_view_selection test_menu; do
    # 不将测试函数放进 if，避免 Bash 禁用函数内的 errexit。
    ( "$test" ) > "$test_dir/test-output" 2>&1
    printf 'PASS %s\n' "$test"
done
[[ $(cat "$test_dir/selected-restart") == selected ]]
[[ $(cat "$test_dir/restarted") == snell-2.service ]]
printf 'All 12 regression tests passed.\n'
