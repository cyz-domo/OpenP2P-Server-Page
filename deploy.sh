#!/usr/bin/env bash
# ==============================================================================
# OpenP2P 管理面板 (openp2p-panel) — Linux & macOS 一键部署与服务管理脚本
# 支持系统：Ubuntu / Debian / CentOS / RHEL / Fedora / Alpine / Arch / macOS 等
# 用法：
#   ./deploy.sh              # 交互式菜单
#   ./deploy.sh start        # 启动后台服务 (默认端口 8377)
#   ./deploy.sh stop         # 停止后台服务
#   ./deploy.sh restart      # 重启服务
#   ./deploy.sh status       # 查看状态
#   ./deploy.sh logs         # 查看运行日志
#   ./deploy.sh service      # 注册为 systemd 开机自启服务 + 全局命令 openp2p-panel (Linux)
#   ./deploy.sh unservice    # 卸载 systemd 服务
#   ./deploy.sh install-cli  # 仅创建系统全局管理命令 openp2p-panel (可在任何目录执行)
#   ./deploy.sh uninstall-cli# 移除全局管理命令
# ==============================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 脚本与服务路径定位
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.server.pid"
LOG_FILE="${SCRIPT_DIR}/server.log"
SERVICE_NAME="openp2p-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CLI_BIN="/usr/local/bin/openp2p-panel"
ALT_CLI_BIN="/usr/bin/openp2p-panel"

# 默认运行参数
DEFAULT_PORT=8377
DEFAULT_HOST="0.0.0.0"

# 打印横幅
print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "========================================================"
    echo "       OpenP2P 管理面板 — 一键部署与系统管理工具        "
    echo "========================================================"
    echo -e "${NC}"
}

# 寻找 Python 3
find_python() {
    local py_candidates=("python3" "python")
    for py in "${py_candidates[@]}"; do
        if command -v "$py" >/dev/null 2>&1; then
            local ver
            ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
            local major
            major=$(echo "$ver" | cut -d. -f1)
            local minor
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
                echo "$py"
                return 0
            fi
        fi
    done
    return 1
}

# 检查环境并返回 Python 路径
check_env() {
    PYTHON_BIN=$(find_python || true)
    if [ -z "$PYTHON_BIN" ]; then
        echo -e "${RED}[错误] 未检测到 Python 3.8 或更高版本！${NC}"
        echo -e "请先安装 Python 3.8+，参考命令："
        echo -e "  - Ubuntu/Debian:  ${YELLOW}sudo apt update && sudo apt install -y python3${NC}"
        echo -e "  - CentOS/RHEL:    ${YELLOW}sudo dnf install -y python3${NC}"
        echo -e "  - Alpine Linux:   ${YELLOW}sudo apk add python3${NC}"
        echo -e "  - macOS:          ${YELLOW}brew install python3${NC}"
        exit 1
    fi
}

# 获取本机 IP 地址列表
get_local_ips() {
    local ips=()
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        for ip in $(hostname -I); do
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$ip" != "127.0.0.1" ]]; then
                ips+=("$ip")
            fi
        done
    elif command -v ip >/dev/null 2>&1; then
        for ip in $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1'); do
            ips+=("$ip")
        done
    elif command -v ifconfig >/dev/null 2>&1; then
        for ip in $(ifconfig | grep -E "inet " | awk '{print $2}' | sed 's/addr://' | grep -v '127.0.0.1'); do
            ips+=("$ip")
        done
    fi
    echo "${ips[@]}"
}

# 检查是否在运行
is_running() {
    # 检查 systemd 服务状态
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        return 0
    fi
    # 检查 PID 文件
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    # 检查进程名
    local pids
    pids=$(pgrep -f "python.*server\.py" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        return 0
    fi
    return 1
}

# 启动后台服务
start_server() {
    check_env
    local port="${1:-$DEFAULT_PORT}"
    local host="${2:-$DEFAULT_HOST}"
    local extra_args="${3:-}"

    if is_running; then
        echo -e "${YELLOW}[提示] OpenP2P 面板已在运行中！${NC}"
        show_status
        return 0
    fi

    # 如果存在已安装的 systemd 服务，优先通过 systemctl 启动
    if [ -f "$SERVICE_FILE" ] && command -v systemctl >/dev/null 2>&1; then
        echo -e "${BLUE}[+] 检测到已安装 systemd 服务，正在通过 systemctl 启动...${NC}"
        systemctl start "$SERVICE_NAME" 2>/dev/null || sudo systemctl start "$SERVICE_NAME" 2>/dev/null || true
        sleep 1
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}${BOLD}[✔] systemd 服务启动成功！${NC}"
            show_status
            return 0
        fi
    fi

    echo -e "${BLUE}[+] 正在启动 OpenP2P 管理面板...${NC}"
    cd "$SCRIPT_DIR"

    nohup "$PYTHON_BIN" server.py --host "$host" --port "$port" $extra_args >> "$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"

    sleep 1.2
    if kill -0 "$new_pid" 2>/dev/null; then
        echo -e "${GREEN}${BOLD}[✔] OpenP2P 面板启动成功！(PID: ${new_pid})${NC}"
        echo -e "访问地址："
        echo -e "  - 本机访问:   ${CYAN}http://localhost:${port}${NC}"
        local ips=($(get_local_ips))
        for ip in "${ips[@]}"; do
            echo -e "  - 局域网访问: ${CYAN}http://${ip}:${port}${NC}"
        done
        echo -e "日志文件:     ${LOG_FILE}"
    else
        echo -e "${RED}[✖] 启动失败，请检查运行日志：${NC}"
        tail -n 20 "$LOG_FILE"
        exit 1
    fi
}

# 前台调试运行
run_foreground() {
    check_env
    local port="${1:-$DEFAULT_PORT}"
    local host="${2:-$DEFAULT_HOST}"
    local extra_args="${3:-}"

    echo -e "${BLUE}[+] 正在前台运行 OpenP2P 管理面板 (Ctrl+C 退出)...${NC}"
    cd "$SCRIPT_DIR"
    exec "$PYTHON_BIN" server.py --host "$host" --port "$port" $extra_args
}

# 停止服务
stop_server() {
    echo -e "${BLUE}[+] 正在停止 OpenP2P 管理面板...${NC}"
    local stopped=0

    # 如果有 systemd 服务正在运行，先停止 systemd
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${BLUE}[+] 正在通过 systemctl 停止服务...${NC}"
        systemctl stop "$SERVICE_NAME" 2>/dev/null || sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        stopped=1
    fi

    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                sleep 1
                if kill -0 "$pid" 2>/dev/null; then
                    kill -9 "$pid" 2>/dev/null || true
                fi
                stopped=1
            fi
        fi
        rm -f "$PID_FILE"
    fi

    # 清理残余进程
    local pids
    pids=$(pgrep -f "python.*server\.py" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        for p in $pids; do
            kill "$p" 2>/dev/null || true
        done
        stopped=1
    fi

    if [ $stopped -eq 1 ]; then
        echo -e "${GREEN}[✔] 面板服务已成功停止。${NC}"
    else
        echo -e "${YELLOW}[!] 未发现运行中的面板进程。${NC}"
    fi
}

# 查看状态
show_status() {
    if is_running; then
        local mode_desc="后台进程"
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            mode_desc="systemd 系统服务"
        elif [ -f "$PID_FILE" ]; then
            mode_desc="后台进程 (PID: $(cat "$PID_FILE" 2>/dev/null || true))"
        fi
        echo -e "服务状态:   ${GREEN}${BOLD}● 运行中 (Active)${NC} [${mode_desc}]"
        echo -e "访问地址："
        echo -e "  - 本机访问:   ${CYAN}http://localhost:${DEFAULT_PORT}${NC}"
        local ips=($(get_local_ips))
        for ip in "${ips[@]}"; do
            echo -e "  - 局域网访问: ${CYAN}http://${ip}:${DEFAULT_PORT}${NC}"
        done
    else
        echo -e "服务状态:   ${RED}○ 未运行 (Stopped)${NC}"
    fi
}

# 查看日志
show_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    fi
    echo -e "${BLUE}[+] 正在监听运行日志 (按 Ctrl+C 退出)：${NC}"
    tail -f -n 50 "$LOG_FILE"
}

# 创建系统全局管理命令 (openp2p-panel)
install_cli() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[错误] 创建系统全局管理命令需要 root 权限，请使用 sudo 执行！${NC}"
        echo -e "示例: ${YELLOW}sudo ./deploy.sh install-cli${NC}"
        exit 1
    fi

    echo -e "${BLUE}[+] 正在创建全局系统管理命令 (${CLI_BIN})...${NC}"
    local target_bin="$CLI_BIN"
    if [ ! -d "/usr/local/bin" ] && [ -d "/usr/bin" ]; then
        target_bin="$ALT_CLI_BIN"
    fi

    cat <<EOF > "$target_bin"
#!/usr/bin/env bash
# OpenP2P Panel Global System Management Command
exec "${SCRIPT_DIR}/deploy.sh" "\$@"
EOF
    chmod +x "$target_bin"
    if [ "$target_bin" = "$CLI_BIN" ] && [ -d "/usr/bin" ] && [ ! -f "$ALT_CLI_BIN" ]; then
        ln -sf "$CLI_BIN" "$ALT_CLI_BIN" 2>/dev/null || true
    fi

    echo -e "${GREEN}${BOLD}[✔] 系统全局命令 openp2p-panel 创建成功！${NC}"
    echo -e "现在可以在任何目录下直接输入：${CYAN}${BOLD}openp2p-panel${NC} 进行管理！"
    echo -e "例如: ${YELLOW}openp2p-panel status${NC} / ${YELLOW}openp2p-panel restart${NC} / ${YELLOW}openp2p-panel logs${NC}"
}

# 移除系统全局管理命令
uninstall_cli() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[错误] 移除系统全局管理命令需要 root 权限，请使用 sudo 执行！${NC}"
        exit 1
    fi
    rm -f "$CLI_BIN" "$ALT_CLI_BIN"
    echo -e "${GREEN}[✔] 已移除全局命令 openp2p-panel。${NC}"
}

# 安装为 systemd 开机自启服务 + 全局命令 (Linux)
install_service() {
    if [ "$(uname -s)" != "Linux" ]; then
        echo -e "${YELLOW}[!] systemd 仅支持 Linux 系统。macOS 用户建议使用 start 后台启动。${NC}"
        return 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[错误] 安装系统服务需要 root 权限，请使用 sudo ./deploy.sh service 运行！${NC}"
        exit 1
    fi

    check_env
    echo -e "${BLUE}[+] 正在配置 systemd 开机自启服务...${NC}"

    local py_path
    py_path=$(command -v "$PYTHON_BIN")

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=OpenP2P Management Panel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${py_path} ${SCRIPT_DIR}/server.py --host 0.0.0.0 --port ${DEFAULT_PORT}
Restart=always
RestartSec=5
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"

    echo -e "${GREEN}${BOLD}[✔] systemd 开机自启服务安装并启动成功！${NC}"

    # 自动创建全局命令
    install_cli

    echo ""
    echo -e "常用管理方式："
    echo -e "  - 全局管理:   ${CYAN}${BOLD}openp2p-panel [start|stop|restart|status|logs]${NC}"
    echo -e "  - systemctl:  ${YELLOW}sudo systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  - 查看日志:   ${YELLOW}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
}

# 卸载 systemd 服务与全局命令
uninstall_service() {
    if [ "$(uname -s)" != "Linux" ]; then
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[错误] 卸载系统服务需要 root 权限，请使用 sudo ./deploy.sh unservice 运行！${NC}"
        exit 1
    fi
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${BLUE}[+] 正在卸载 systemd 服务...${NC}"
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        echo -e "${GREEN}[✔] systemd 服务已卸载。${NC}"
    else
        echo -e "${YELLOW}[!] 未发现已安装的 systemd 服务。${NC}"
    fi
    uninstall_cli
}

# 交互式主菜单
interactive_menu() {
    print_banner
    check_env
    echo -e "当前检测到 Python: ${CYAN}${PYTHON_BIN}${NC}"
    echo ""
    echo "请选择操作："
    echo "  1) 启动后台运行 (默认端口 8377)"
    echo "  2) 前台交互运行 (排查问题)"
    echo "  3) 停止后台面板"
    echo "  4) 重启面板"
    echo "  5) 查看运行状态与访问链接"
    echo "  6) 查看实时日志"
    if [ "$(uname -s)" = "Linux" ]; then
        echo "  7) 安装为 systemd 开机自启服务 + 全局命令 (需 sudo)"
        echo "  8) 卸载 systemd 服务与全局命令 (需 sudo)"
        echo "  9) 仅创建系统全局命令 (openp2p-panel，需 sudo)"
    fi
    echo "  0) 退出"
    echo ""
    read -rp "请输入选项 [0-9]: " choice

    case "$choice" in
        1)
            read -rp "请输入监听端口 [默认 8377]: " input_port
            port="${input_port:-8377}"
            start_server "$port"
            ;;
        2)
            read -rp "请输入监听端口 [默认 8377]: " input_port
            port="${input_port:-8377}"
            run_foreground "$port"
            ;;
        3)
            stop_server
            ;;
        4)
            stop_server
            sleep 1
            start_server
            ;;
        5)
            show_status
            ;;
        6)
            show_logs
            ;;
        7)
            install_service
            ;;
        8)
            uninstall_service
            ;;
        9)
            install_cli
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${RED}[错误] 无效的选项！${NC}"
            exit 1
            ;;
    esac
}

# 主入口参数解析
main() {
    case "$1" in
        start)
            shift
            start_server "$@"
            ;;
        run)
            shift
            run_foreground "$@"
            ;;
        stop)
            stop_server
            ;;
        restart)
            stop_server
            sleep 1
            shift
            start_server "$@"
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        service)
            install_service
            ;;
        unservice)
            uninstall_service
            ;;
        install-cli)
            install_cli
            ;;
        uninstall-cli)
            uninstall_cli
            ;;
        help|--help|-h)
            print_banner
            echo "用法: $0 [start|run|stop|restart|status|logs|service|unservice|install-cli|uninstall-cli]"
            ;;
        *)
            interactive_menu
            ;;
    esac
}

main "$@"
