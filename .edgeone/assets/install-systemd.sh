#!/usr/bin/env bash
# ==============================================================================
# OpenP2P 管理面板 — Linux systemd 系统服务与全局命令一键安装脚本
# 支持系统：Ubuntu / Debian / CentOS / RHEL / Fedora / Alpine / Arch / 树莓派
# 用法：
#   sudo ./install-systemd.sh [--port 8377] [--host 0.0.0.0] [--auth 访问口令]
# ==============================================================================

set -e

# 终端色彩
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="openp2p-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="${SCRIPT_DIR}/server.log"
CLI_BIN="/usr/local/bin/openp2p-panel"
ALT_CLI_BIN="/usr/bin/openp2p-panel"

# 默认参数
PORT=8377
HOST="0.0.0.0"
AUTH=""
UPSTREAM=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        --host|-h)
            HOST="$2"
            shift 2
            ;;
        --auth|-a)
            AUTH="$2"
            shift 2
            ;;
        --upstream|-u)
            UPSTREAM="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${CYAN}${BOLD}"
echo "=========================================================="
echo "    OpenP2P 管理面板 — Linux systemd 系统服务安装向导     "
echo "=========================================================="
echo -e "${NC}"

# 1. 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[错误] 安装系统服务需要 root 权限，请使用 sudo 运行本脚本！${NC}"
    echo -e "示例: ${YELLOW}sudo bash $0${NC}"
    exit 1
fi

# 2. 检查操作系统是否为 Linux
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}[错误] systemd 仅在 Linux 系统上可用！macOS 用户请使用 ./deploy.sh start${NC}"
    exit 1
fi

# 3. 检查 systemd 是否可用
if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${RED}[错误] 未检测到 systemctl，本系统可能未使用 systemd 初始化！${NC}"
    echo -e "您可以直接使用 ${YELLOW}./deploy.sh start${NC} 进行后台运行。"
    exit 1
fi

# 4. 检查 Python 3 环境
find_python() {
    local candidates=("python3" "python")
    for py in "${candidates[@]}"; do
        if command -v "$py" >/dev/null 2>&1; then
            local ver
            ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
            local major=$(echo "$ver" | cut -d. -f1)
            local minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
                echo "$py"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON_BIN=$(find_python || true)
if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[错误] 未检测到 Python 3.8+ 环境！${NC}"
    echo -e "请先安装 Python 3.8 或更高版本："
    echo -e "  - Ubuntu/Debian:  ${YELLOW}apt update && apt install -y python3${NC}"
    echo -e "  - CentOS/RHEL:    ${YELLOW}dnf install -y python3${NC}"
    echo -e "  - Alpine Linux:   ${YELLOW}apk add python3${NC}"
    exit 1
fi

PY_PATH=$(command -v "$PYTHON_BIN")
echo -e "[+] 检测到 Python: ${CYAN}${PY_PATH}${NC}"

# 5. 确保脚本拥有执行权限
chmod +x "${SCRIPT_DIR}/deploy.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/server.py" 2>/dev/null || true

# 6. 生成 systemd service 文件
echo -e "${BLUE}[+] 正在配置 systemd 系统服务 (/etc/systemd/system/${SERVICE_NAME}.service)...${NC}"

EXTRA_ARGS=""
if [ -n "$AUTH" ]; then
    EXTRA_ARGS="--auth ${AUTH}"
fi
if [ -n "$UPSTREAM" ]; then
    EXTRA_ARGS="${EXTRA_ARGS} --upstream ${UPSTREAM}"
fi

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=OpenP2P Management Panel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PY_PATH} ${SCRIPT_DIR}/server.py --host ${HOST} --port ${PORT} ${EXTRA_ARGS}
Restart=always
RestartSec=5
KillMode=mixed
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

# 7. 重载 systemd 并启动服务
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# 8. 创建全局快捷管理命令 openp2p-panel
echo -e "${BLUE}[+] 正在创建全局系统管理命令 (${CLI_BIN})...${NC}"
TARGET_CLI="$CLI_BIN"
if [ ! -d "/usr/local/bin" ] && [ -d "/usr/bin" ]; then
    TARGET_CLI="$ALT_CLI_BIN"
fi

cat <<EOF > "$TARGET_CLI"
#!/usr/bin/env bash
# OpenP2P Panel Global System CLI
exec "${SCRIPT_DIR}/deploy.sh" "\$@"
EOF
chmod +x "$TARGET_CLI"

# 如果两个目录都存在，建立软链接确保任何环境均可执行
if [ "$TARGET_CLI" = "$CLI_BIN" ] && [ -d "/usr/bin" ] && [ ! -f "$ALT_CLI_BIN" ]; then
    ln -sf "$CLI_BIN" "$ALT_CLI_BIN" 2>/dev/null || true
fi

# 9. 检索本机 IP 并输出完成状态
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
    fi
    echo "${ips[@]}"
}

echo ""
echo -e "${GREEN}${BOLD}=========================================================="
echo "    [✔] OpenP2P 管理面板 systemd 系统服务安装成功！         "
echo "==========================================================${NC}"
echo ""
echo -e "服务状态:   ${GREEN}${BOLD}● 运行中 (Active) 开机自动启动${NC}"
echo -e "服务名称:   ${CYAN}${SERVICE_NAME}${NC}"
echo -e "访问地址："
echo -e "  - 本机访问:   ${CYAN}http://localhost:${PORT}${NC}"
LOCAL_IPS=($(get_local_ips))
for ip in "${LOCAL_IPS[@]}"; do
    echo -e "  - 局域网访问: ${CYAN}http://${ip}:${PORT}${NC}"
done
echo -e "日志文件:   ${LOG_FILE}"
echo ""
echo -e "${BOLD}【全新系统级管理命令】${NC}"
echo -e "您现在可以在终端任意目录下直接输入：${CYAN}${BOLD}openp2p-panel${NC} 进行管理！"
echo -e "  - 查看面板菜单:  ${YELLOW}openp2p-panel${NC}"
echo -e "  - 查看服务状态:  ${YELLOW}openp2p-panel status${NC}  或  ${YELLOW}systemctl status ${SERVICE_NAME}${NC}"
echo -e "  - 停止面板服务:  ${YELLOW}openp2p-panel stop${NC}    或  ${YELLOW}systemctl stop ${SERVICE_NAME}${NC}"
echo -e "  - 重启面板服务:  ${YELLOW}openp2p-panel restart${NC} 或  ${YELLOW}systemctl restart ${SERVICE_NAME}${NC}"
echo -e "  - 查看实时日志:  ${YELLOW}openp2p-panel logs${NC}    或  ${YELLOW}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "  - 卸载系统服务:  ${YELLOW}sudo openp2p-panel unservice${NC}"
echo ""
