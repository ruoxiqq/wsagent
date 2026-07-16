#!/bin/bash
# ============================================================
# 靶机 Web 服务安装脚本
# 在 CentOS 7 虚拟机内执行
# 安装 Apache + PHP 并部署漏洞上传服务
# ============================================================

set -e

echo "=========================================="
echo "  靶机 Web 服务安装"
echo "=========================================="

# 1. 安装 Apache 和 PHP
echo "[1/5] 安装 Apache 和 PHP..."
yum install -y httpd php php-cli >/dev/null 2>&1

# 2. 创建 Web 目录
echo "[2/5] 创建 Web 目录..."
WEB_DIR="/var/www/vulnerable"
mkdir -p "$WEB_DIR/uploads"

# 3. 复制网站文件
echo "[3/5] 部署网站文件..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp -f "$SCRIPT_DIR/www/index.html" "$WEB_DIR/"
cp -f "$SCRIPT_DIR/www/upload.php" "$WEB_DIR/"
cp -f "$SCRIPT_DIR/www/list.php" "$WEB_DIR/"
cp -f "$SCRIPT_DIR/www/uploads/.htaccess" "$WEB_DIR/uploads/"
cp -f "$SCRIPT_DIR/www/uploads/index.html" "$WEB_DIR/uploads/"

# 4. 配置 Apache
echo "[4/5] 配置 Apache..."
cp -f "$SCRIPT_DIR/apache-config/vulnerable.conf" /etc/httpd/conf.d/
# 确保 .htaccess 生效（AllowOverride All 已在配置中设置）
# 确保 mod_rewrite 加载
sed -i 's/^#LoadModule rewrite_module/LoadModule rewrite_module/' /etc/httpd/conf/httpd.conf 2>/dev/null || true

# SELinux：放行 8080 端口给 httpd（CentOS 默认仅允许 80/443 等）
echo "    [SELinux] 放行 8080 端口..."
semanage port -a -t http_port_t -p tcp 8080 2>/dev/null || \
  semanage port -m -t http_port_t -p tcp 8080 2>/dev/null || true
# 允许 httpd 发起网络连接（beacon 外联 C2 需要）
setsebool -P httpd_can_network_connect on 2>/dev/null || true

# 5. 设置权限
echo "[5/5] 设置权限..."
chown -R apache:apache "$WEB_DIR"
chmod -R 755 "$WEB_DIR"
chmod 777 "$WEB_DIR/uploads"

# 添加 apache 用户到 input 组（键盘记录功能需要）
usermod -aG input apache 2>/dev/null || true

# 启动 Apache
systemctl restart httpd
systemctl enable httpd

echo ""
echo "=========================================="
echo "  安装完成!"
echo "=========================================="
echo "  Web 服务地址: http://<虚拟机IP>:8080"
echo "  上传目录:     $WEB_DIR/uploads/"
echo "  Apache 日志:  /var/log/httpd/"
echo "=========================================="
