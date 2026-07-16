#!/bin/bash
# ============================================================
# 环境重置脚本 - 清除攻防残留，恢复初始状态
# 在 CentOS 7 虚拟机内执行
# 用法: sudo bash reset-env.sh
# ============================================================

echo "╔══════════════════════════════════════════════╗"
echo "║  环境重置 - 清除攻防残留                    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] 请使用 root 权限执行: sudo bash reset-env.sh"
    exit 1
fi

# 1. 清除上传目录中的所有文件
echo "[1/5] 清除上传目录..."
UPLOAD_DIR="/var/www/vulnerable/uploads"
if [ -d "$UPLOAD_DIR" ]; then
    find "$UPLOAD_DIR" -type f ! -name '.htaccess' ! -name 'index.html' -delete
    echo "    [+] 上传目录已清空"
fi

# 2. 终止残留 Beacon 进程
echo "[2/5] 终止残留 Beacon 进程..."
PIDS=$(ps aux | grep -E '(beacon|\.system_update)' | grep -v grep | awk '{print $2}')
if [ -n "$PIDS" ]; then
    kill -9 $PIDS 2>/dev/null
    echo "    [+] 已终止进程: $PIDS"
else
    echo "    [+] 无残留进程"
fi

# 3. 清除 Beacon 文件
echo "[3/5] 清除残留文件..."
rm -f /tmp/.system_update.py /tmp/beacon.py 2>/dev/null
rm -rf /tmp/quarantine 2>/dev/null
echo "    [+] 残留文件已清除"

# 4. 清除 iptables 规则
echo "[4/5] 重置 iptables 规则..."
iptables -F OUTPUT 2>/dev/null
echo "    [+] iptables OUTPUT 链已重置"

# 5. 重启 Apache
echo "[5/5] 重启 Apache..."
systemctl restart httpd
echo "    [+] Apache 已重启"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  环境已重置! 可以重新开始攻防演练。         ║"
echo "╚══════════════════════════════════════════════╝"
