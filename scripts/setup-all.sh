#!/bin/bash
# ============================================================
# WebShell 攻防演示系统 - CentOS 靶机部署脚本
# 在 CentOS 7 虚拟机内执行（仅部署靶机服务+防御智能体）
# C2 远控服务部署在 Windows 宿主机上，不在此脚本范围
# 用法: sudo bash setup-all.sh
# ============================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "╔══════════════════════════════════════════════╗"
echo "║  WebShell 攻防演示系统 - 靶机部署           ║"
echo "║  (C2 服务在 Windows 宿主机上单独启动)        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] 请使用 root 权限执行: sudo bash setup-all.sh"
    exit 1
fi

# ========== 1. 系统初始化 ==========
echo "[1/5] 系统初始化..."
yum install -y epel-release >/dev/null 2>&1
yum install -y httpd php php-cli python3 iptables-services >/dev/null 2>&1
echo "    [+] 依赖安装完成 (Apache, PHP, Python3)"

# ========== 2. 部署靶机 Web 服务 ==========
echo "[2/5] 部署靶机 Web 服务..."
bash "$PROJECT_ROOT/target-server/install.sh" 2>/dev/null
echo "    [+] 靶机 Web 服务部署完成 (端口 8080)"

# ========== 3. 部署防御智能体(多智能体版) ==========
echo "[3/5] 部署多智能体防御系统..."
# 原地部署: 直接在项目目录运行, 不拷贝到 /opt (代码位置无关, 靠 __file__ 解析导入)
DEFENSE_DIR="$PROJECT_ROOT/defense-agent"
echo "    防御智能体位于 $DEFENSE_DIR (原地运行, 无需拷贝到 /opt)"
# 校验关键模块齐全(避免漏拷导致 ModuleNotFoundError)
for _f in multi_agent_defense.py config.py llm_backend.py event_bus.py action_executor.py start-defense.sh; do
    if [ ! -f "$DEFENSE_DIR/$_f" ]; then
        echo "    [!] 缺少必要文件: $DEFENSE_DIR/$_f"
        exit 1
    fi
done
chmod +x "$DEFENSE_DIR/start-defense.sh"
# 保留旧版单体防御作为对照(legacy), 仅当存在时复制
[ -f "$PROJECT_ROOT/defense-agent/defense_agent.py" ] && \
    cp -f "$PROJECT_ROOT/defense-agent/defense_agent.py" "$DEFENSE_DIR/defense_agent_legacy.py"
[ -f "$PROJECT_ROOT/defense-agent/defense_console.py" ] && \
    cp -f "$PROJECT_ROOT/defense-agent/defense_console.py" "$DEFENSE_DIR/defense_console_legacy.py"
echo "    [+] 模块校验通过, 启动方式: cd $DEFENSE_DIR && sudo bash start-defense.sh"

# ========== 4. 准备 WebShell 样本 ==========
echo "[4/5] 准备 WebShell 样本..."
SHELL_DIR="/opt/webshell"
mkdir -p "$SHELL_DIR"
cp -f "$PROJECT_ROOT/webshell/webshell.php" "$SHELL_DIR/"
cp -f "$PROJECT_ROOT/webshell/beacon.py" "$SHELL_DIR/"
echo "    [+] WebShell 样本在 $SHELL_DIR"

# ========== 5. 配置权限和防火墙 ==========
echo "[5/5] 配置权限和防火墙..."
# 添加 apache 用户到 input 组（键盘记录功能需要）
usermod -aG input apache 2>/dev/null || true

# 开放 Web 服务端口（C2 端口 8888 不需要在靶机开放，C2 在宿主机上）
firewall-cmd --permanent --add-port=8080/tcp 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

# 重启 Apache
systemctl restart httpd
systemctl enable httpd

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  靶机部署完成!                                       ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  [靶机 - CentOS VM]                                   ║"
echo "║  Web 服务:     http://<本机IP>:8080                  ║"
echo "║  防御智能体:   cd defense-agent &&                 ║"
echo "║                sudo bash start-defense.sh (原地运行)  ║"
echo "║  WebShell样本: /opt/webshell/                        ║"
echo "║                                                      ║"
echo "║  [C2 - Windows 宿主机]                                ║"
echo "║  启动C2:      双击 c2-server\\start-c2.bat           ║"
echo "║  或CMD运行:   cd c2-server && python c2_console.py   ║"
echo "║  C2监听:      0.0.0.0:8888                           ║"
echo "║                                                      ║"
echo "║  防火墙放行(管理员CMD):                               ║"
echo "║  netsh advfirewall firewall add rule name=\"C2-8888\" ║"
echo "║  dir=in action=allow protocol=TCP localport=8888     ║"
echo "║                                                      ║"
echo "║  详细操作请参考: docs/deployment-guide.md            ║"
echo "╚══════════════════════════════════════════════════════╝"
