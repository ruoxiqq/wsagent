# WebShell 综合攻防演示系统

> 基于 AI 智能体的 WebShell 攻防仿真平台 · 安全教学专用

## 系统简介

本系统是一套可完整实操、可视化对抗的 WebShell 攻防仿真平台。攻击者通过文件上传漏洞部署带远控持久化能力的 WebShell，防御智能体自主监控并自动识别、拦截、处置入侵行为，形成攻防双向对抗演示。

## 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                    Windows 宿主机 (笔记本)                     │
│                                                              │
│  ┌───────────────┐                ┌───────────────────────┐  │
│  │   攻击者浏览器  │  上传WebShell  │   C2 远控服务           │  │
│  │   (操作面板)    │ ────────────► │   c2_console.py        │  │
│  │               │                │   监听: 0.0.0.0:4444   │  │
│  │               │  ◄───────────  │   (start-c2.bat)       │  │
│  └───────────────┘   WebShell页面  └───────────┬───────────┘  │
│                                                  │            │
└──────────────────────────────────────────────────┼────────────┘
                                                   │
                                    C2 通信 (TCP 4444)
                                    192.168.163.1 ←→ 192.168.62.128
                                                   │
┌──────────────────────────────────────────────────┼────────────┐
│              CentOS 7 虚拟机 (VMware)             │            │
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
│  │  ┌─────────┐ ┌───────────┐ ┌─────────┐     │              │
│  │  │文件监控  │ │网络监控    │ │进程监控  │     │              │
│  │  │(WebShell)│ │(C2外联)   │ │(Beacon) │     │              │
│  │  └────┬────┘ └─────┬─────┘ └────┬────┘     │              │
│  │       └──────┬─────┴────────────┘          │              │
│  │         自动处置引擎                         │              │
│  │  (隔离文件/阻断IP/终止进程/告警)              │              │
│  └─────────────────────────────────────────────┘              │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**架构说明**：
- **C2 远控服务** 部署在 Windows 宿主机上，攻击者直接在 Windows 终端操作 C2 控制台
- **靶机 Web 服务 + 防御智能体** 部署在 CentOS 7 虚拟机内
- Beacon 从虚拟机主动外联到宿主机 C2（跨网络通信），防御智能体可检测到真实的网络外联行为

## 网络配置

| 角色 | IP 地址 | 说明 |
|------|---------|------|
| Windows 宿主机 (C2) | 192.168.163.1 | C2 服务监听 4444 端口 |
| CentOS 虚拟机 (靶机) | 192.168.62.128 | Web 服务 8080 端口 |

> 两台机器需能互相 ping 通。Windows 防火墙需放行 4444 端口入站。

## 核心功能

### 攻击侧
- 存在文件上传漏洞的 Web 接口（支持手动上传）
- PHP WebShell 后门（Web 命令执行面板）
- C2 Beacon 持久化通信（Python 反向连接）
- 主机键盘记录（远程启停 + 数据回传）

### C2 远控
- 远程下发任意系统命令
- 键盘记录一键启停
- 键盘数据统一查看

### 防御侧
- 文件监控 - 自动检测 WebShell 上传
- 网络监控 - 检测 C2 外联通信（跨网络到宿主机 4444 端口）
- 进程监控 - 检测键盘记录/Beacon 进程
- 自动处置 - 隔离文件/阻断IP/终止进程/告警
- 一键启停 - 清晰对比有无防御效果

## 快速部署

### 第一步：部署 CentOS 靶机

```bash
# 1. 传输项目到 CentOS 7 虚拟机
scp -r webshell-attack-defense-system root@192.168.62.128:/root/

# 2. 在虚拟机中执行部署
cd /root/webshell-attack-defense-system
sudo bash scripts/setup-all.sh

# 3. 验证 Web 服务
# 浏览器访问 http://192.168.62.128:8080
```

### 第二步：在 Windows 上启动 C2

```cmd
# 1. Windows 防火墙放行 4444 端口（管理员 CMD）
netsh advfirewall firewall add rule name="C2-4444" dir=in action=allow protocol=TCP localport=4444

# 2. 进入 C2 目录并启动
cd F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\c2-server
start-c2.bat
```

### 第三步：在 CentOS 上启动防御智能体

```bash
cd /opt/defense-agent
sudo bash start-defense.sh
# 输入 on 开启防护，off 关闭防护
```

## 使用方式

### 启动 C2 控制台（Windows）
```cmd
# 方式一：双击
c2-server\start-c2.bat

# 方式二：CMD 命令
cd c2-server
python c2_console.py
```

### 启动防御智能体（CentOS）
```bash
cd /opt/defense-agent
sudo bash start-defense.sh
# 输入 on 开启防护，off 关闭防护
```

### 重置环境（CentOS）
```bash
sudo bash /root/webshell-attack-defense-system/scripts/reset-env.sh
```

## 目录结构

```
webshell-attack-defense-system/
├── target-server/          # 靶机 Web 服务 [部署到 CentOS]
│   ├── install.sh          # 安装脚本
│   ├── www/                # 网站文件
│   │   ├── index.html      # 上传表单
│   │   ├── upload.php      # 漏洞上传接口
│   │   ├── list.php        # 文件列表
│   │   └── uploads/        # 上传目录
│   └── apache-config/      # Apache 配置
├── webshell/               # WebShell 样本
│   ├── webshell.php        # PHP WebShell (默认连接 192.168.163.1:4444)
│   └── beacon.py           # C2 Beacon (默认连接 192.168.163.1:4444)
├── c2-server/              # C2 远控服务 [在 Windows 上运行]
│   ├── c2_server.py        # C2 服务器
│   ├── c2_console.py       # 操作控制台
│   ├── start-c2.bat        # Windows 启动脚本 ★
│   └── start-c2.sh         # Linux 启动脚本 (备用)
├── defense-agent/          # 防御智能体 [部署到 CentOS]
│   ├── defense_agent.py    # 防御主程序
│   ├── defense_console.py  # 防御控制台
│   └── start-defense.sh    # 启动脚本
├── scripts/                # 辅助脚本
│   ├── setup-all.sh        # CentOS 靶机部署
│   └── reset-env.sh        # 环境重置
└── docs/
    └── deployment-guide.md # 超详细实操文档
```

## 技术栈

| 组件 | 运行位置 | 技术 |
|------|---------|------|
| 靶机 Web 服务 | CentOS VM | Apache HTTP Server + PHP |
| WebShell 后门 | CentOS VM | PHP（命令执行 + Beacon 部署） |
| C2 Beacon | CentOS VM | Python 3（Socket + Threading + struct） |
| C2 服务器 | **Windows 宿主机** | Python 3（Socket Server + 多线程） |
| 防御智能体 | CentOS VM | Python 3（文件扫描 + 网络监控 + 进程监控） |

## 安全声明

**本系统仅供安全教学演示使用！**

- 所有组件仅限在隔离的虚拟机环境中运行
- 严禁用于任何非授权的真实系统
- WebShell 样本和 C2 工具具有真实攻击能力，请妥善保管
- 使用者需承担因不当使用产生的全部法律责任

## 详细文档

完整的分步式实操部署文档请参阅：[docs/deployment-guide.md](docs/deployment-guide.md)

覆盖从 VMware 配置到攻防对抗全流程，每一步标注命令、界面操作和预期现象。
