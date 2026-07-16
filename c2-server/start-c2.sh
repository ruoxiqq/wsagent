#!/bin/bash
# ============================================================
# C2 远控服务启动脚本
# 在 CentOS 7 虚拟机内执行
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  C2 远控服务启动"
echo "=========================================="

# 检查 Python3
if ! command -v python3 &>/dev/null; then
    echo "[!] 未找到 Python3，正在安装..."
    yum install -y python3 >/dev/null 2>&1
fi

echo "[*] 启动 C2 控制台..."
echo "[*] 监听端口: 4444"
echo "[*] 按 Ctrl+C 退出"
echo "=========================================="
echo ""

cd "$SCRIPT_DIR"
python3 c2_console.py
