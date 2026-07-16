#!/bin/bash
# ============================================================
# 防御智能体启动脚本
# 在 CentOS 7 虚拟机内执行（需要 root 权限）
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  防御智能体启动"
echo "=========================================="

# 检查是否为 root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] 防御智能体需要 root 权限运行（用于 iptables 和进程管理）"
    echo "[!] 请使用: sudo bash start-defense.sh"
    exit 1
fi

# 检查 Python3
if ! command -v python3 &>/dev/null; then
    echo "[!] 未找到 Python3，正在安装..."
    yum install -y python3 >/dev/null 2>&1
fi

echo "[*] 启动防御智能体控制台..."
echo "[*] 首次启动后防护默认关闭，输入 'on' 开启防护"
echo "=========================================="
echo ""

cd "$SCRIPT_DIR"
python3 defense_console.py
