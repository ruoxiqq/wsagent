#!/usr/bin/env python3
"""
防御智能体

功能：
  1. 文件监控 - 监控上传目录，检测 WebShell 上传
  2. 网络监控 - 检测 C2 外联通信
  3. 进程监控 - 检测键盘记录、反向 Beacon 等恶意进程
  4. 自动处置 - 拦截/隔离/查杀/告警闭环
  5. 一键启停 - 支持防护模式开关

安全警告：此程序为安全教学演示用的防御智能体！
"""

import os
import sys
import time
import threading
import subprocess
import re
import json
import signal
from datetime import datetime

# ========== 配置 ==========
UPLOAD_DIR = '/var/www/vulnerable/uploads/'
QUARANTINE_DIR = '/tmp/quarantine'
C2_PORT = 8888
C2_HOST_IP = '192.168.163.1'  # Windows 宿主机 C2 服务器 IP（跨网络外联检测）
WEB_SERVER_USER = 'apache'
KNOWN_BAD_PROCESSES = [
    '/tmp/.system_update.py',   # WebShell 部署的 Beacon
    'beacon.py',                # 独立 Beacon
]

# WebShell 特征规则
WEBSHELL_PATTERNS = [
    (r'eval\s*\(', 'eval() 函数调用'),
    (r'assert\s*\(', 'assert() 函数调用'),
    (r'system\s*\(', 'system() 命令执行'),
    (r'exec\s*\(', 'exec() 命令执行'),
    (r'shell_exec\s*\(', 'shell_exec() 命令执行'),
    (r'passthru\s*\(', 'passthru() 命令执行'),
    (r'proc_open\s*\(', 'proc_open() 进程操作'),
    (r'popen\s*\(', 'popen() 进程操作'),
    (r'base64_decode\s*\(', 'base64 解码（常见混淆）'),
    (r'str_rot13\s*\(', 'str_rot13（混淆）'),
    (r'gzinflate\s*\(', 'gzinflate（压缩混淆）'),
    (r'str_replace\s*\(.*chr\s*\(', 'chr+str_replace 混淆'),
    (r'\$_(POST|GET|REQUEST|COOKIE)\s*\[', '用户输入直接作为命令'),
    (r'preg_replace\s*\(.*\/e', 'preg_replace /e 修饰符执行'),
    (r'create_function\s*\(', 'create_function() 动态函数'),
    (r'call_user_func\s*\(', 'call_user_func() 动态调用'),
    (r'fsockopen\s*\(', 'fsockopen 网络连接'),
    (r'socket_create\s*\(', 'socket_create 网络连接'),
    (r'file_put_contents\s*\(.*\$_(POST|GET)', '用户输入写入文件'),
    (r'move_uploaded_file', '文件上传处理'),
    (r'nohup\s+python', '后台执行 Python（Beacon 部署特征）'),
    (r'struct\.unpack', '二进制数据处理（键盘记录特征）'),
    (r'/dev/input/event', '键盘设备读取（键盘记录特征）'),
    (r'keylog', '键盘记录关键词'),
    (r'socket\.connect', 'Socket 连接（C2 通信特征）'),
]

# 恶意网络连接特征
SUSPICIOUS_PORTS = [8888, 1337, 31337, 8080, 9999, 5555]
SUSPICIOUS_OUTBOUND = [
    (r'python.*connect', 'Python 反向连接'),
]

# 恶意进程特征
SUSPICIOUS_PROCESS_PATTERNS = [
    (r'/tmp/\.\w+\.py', '隐藏 Python 脚本（临时目录）'),
    (r'beacon\.py', 'Beacon 后门程序'),
    (r'/dev/input/event', '读取键盘设备的进程'),
    (r'keylog', '键盘记录进程'),
]


class DefenseAgent:
    """防御智能体主控"""

    def __init__(self):
        self.running = False
        self.active = False       # 防护是否激活
        self.threads = []
        self.alerts = []          # 告警列表
        self.alerts_lock = threading.Lock()
        self.actions = []         # 处置记录
        self.actions_lock = threading.Lock()
        self.scan_count = 0       # 扫描次数
        self.threats_blocked = 0  # 拦截威胁数
        self.known_files = set()  # 已知正常文件
        self._init_quarantine()

    def _init_quarantine(self):
        """初始化隔离目录"""
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    def add_alert(self, level, category, message, detail=''):
        """添加告警"""
        with self.alerts_lock:
            alert = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': level,       # CRITICAL / WARNING / INFO
                'category': category,  # FILE / NETWORK / PROCESS
                'message': message,
                'detail': detail,
            }
            self.alerts.append(alert)
            if len(self.alerts) > 500:
                self.alerts = self.alerts[-500:]

            # 打印告警
            icons = {'CRITICAL': '[!!!]', 'WARNING': '[!]', 'INFO': '[*]'}
            colors = {'CRITICAL': '\033[91m', 'WARNING': '\033[93m', 'INFO': '\033[92m'}
            reset = '\033[0m'
            icon = icons.get(level, '[*]')
            color = colors.get(level, '')
            print("{}{} {} [{}] {}{} {}".format(
                color, icon, alert['time'], category, message, detail, reset
            ))

    def add_action(self, action_type, target, result):
        """记录处置动作"""
        with self.actions_lock:
            self.actions.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': action_type,
                'target': target,
                'result': result,
            })
            if len(self.actions) > 500:
                self.actions = self.actions[-500:]

    # ========== 文件监控 ==========

    def scan_file(self, filepath):
        """扫描单个文件是否为 WebShell"""
        try:
            with open(filepath, 'r', errors='replace') as f:
                content = f.read(500000)  # 最多读取 500KB
        except Exception:
            return False, []

        matches = []
        for pattern, desc in WEBSHELL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(desc)

        is_malicious = len(matches) >= 2  # 命中2条以上规则判定为恶意
        return is_malicious, matches

    def file_monitor_loop(self):
        """文件监控循环"""
        self.add_alert('INFO', 'FILE', '文件监控启动', '监控目录: ' + UPLOAD_DIR)

        while self.running:
            if not self.active:
                time.sleep(2)
                continue

            try:
                if os.path.isdir(UPLOAD_DIR):
                    for item in os.listdir(UPLOAD_DIR):
                        if item in ('.', '..', '.htaccess', 'index.html'):
                            continue
                        filepath = os.path.join(UPLOAD_DIR, item)

                        if not os.path.isfile(filepath):
                            continue

                        # 检查是否已处理过
                        if filepath in self.known_files:
                            continue

                        self.known_files.add(filepath)

                        # 检查是否为可执行脚本
                        is_script = item.endswith(('.php', '.py', '.phtml', '.php5', '.php7'))

                        if is_script:
                            is_malicious, matches = self.scan_file(filepath)

                            if is_malicious:
                                self.add_alert('CRITICAL', 'FILE',
                                    '检测到 WebShell 上传: {}'.format(item),
                                    '命中规则: ' + ', '.join(matches)
                                )
                                self.threats_blocked += 1
                                self.quarantine_file(filepath)
                            elif matches:
                                self.add_alert('WARNING', 'FILE',
                                    '可疑文件上传: {}'.format(item),
                                    '命中规则: ' + ', '.join(matches)
                                )

            except Exception as e:
                self.add_alert('WARNING', 'FILE', '文件监控异常', str(e))

            time.sleep(1)  # 每秒扫描一次

    def quarantine_file(self, filepath):
        """隔离文件"""
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(QUARANTINE_DIR, filename + '.' + str(int(time.time())))
            os.rename(filepath, quarantine_path)
            self.add_action('QUARANTINE', filepath, '已隔离到 ' + quarantine_path)
            self.add_alert('INFO', 'FILE', '文件已隔离', '{} -> {}'.format(filepath, quarantine_path))

            # 同时删除可能的 .htaccess 引用
            htaccess = os.path.join(UPLOAD_DIR, '.htaccess')
            if os.path.exists(htaccess):
                pass  # 不删除配置文件
        except Exception as e:
            self.add_action('QUARANTINE', filepath, '隔离失败: ' + str(e))
            self.add_alert('WARNING', 'FILE', '文件隔离失败', str(e))

    # ========== 网络监控 ==========

    def network_monitor_loop(self):
        """网络监控循环"""
        self.add_alert('INFO', 'NETWORK', '网络监控启动',
                        '监控 C2 端口: {} | C2 IP: {}'.format(C2_PORT, C2_HOST_IP))

        while self.running:
            if not self.active:
                time.sleep(2)
                continue

            try:
                # 使用 ss 命令检查网络连接
                result = subprocess.run(
                    ['ss', '-tunap'],
                    capture_output=True, text=True, timeout=5
                )
                connections = result.stdout

                for line in connections.split('\n'):
                    # 检测 C2 端口连接 或 到 C2 主机 IP 的外联
                    is_c2_port = str(C2_PORT) in line
                    is_c2_ip = C2_HOST_IP in line

                    if not (is_c2_port or is_c2_ip):
                        continue

                    # 排除本地 LISTEN（靶机自身不监听 C2 端口，但保留检查）
                    if 'LISTEN' in line:
                        continue

                    # 检测到 C2 外联
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[4] if len(parts) > 4 else 'unknown'
                        peer_addr = parts[5] if len(parts) > 5 else 'unknown'
                        process_info = parts[-1] if parts else ''

                        if 'ESTAB' in line or 'SYN' in line:
                            # 判断是端口匹配还是 IP 匹配
                            reason = 'C2端口' if is_c2_port else 'C2主机IP'
                            self.add_alert('CRITICAL', 'NETWORK',
                                '检测到 C2 外联通信 [{}]'.format(reason),
                                '连接: {} -> {} | 进程: {}'.format(local_addr, peer_addr, process_info)
                            )
                            self.threats_blocked += 1
                            self.block_connection(peer_addr, process_info)

            except Exception as e:
                pass  # ss 命令可能偶尔失败

            time.sleep(2)

    def block_connection(self, peer_addr, process_info):
        """阻断网络连接"""
        try:
            # 提取 IP 地址
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', peer_addr)
            if ip_match:
                ip = ip_match.group(1)
                # 使用 iptables 阻断
                subprocess.run(
                    ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    capture_output=True, timeout=5
                )
                self.add_action('BLOCK_IP', ip, '已添加 iptables OUTPUT DROP 规则')
                self.add_alert('INFO', 'NETWORK', '已阻断外联 IP', ip)
        except Exception as e:
            self.add_action('BLOCK_IP', peer_addr, '阻断失败: ' + str(e))

    # ========== 进程监控 ==========

    def process_monitor_loop(self):
        """进程监控循环"""
        self.add_alert('INFO', 'PROCESS', '进程监控启动', '监控恶意进程特征')

        while self.running:
            if not self.active:
                time.sleep(2)
                continue

            try:
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True, text=True, timeout=5
                )
                processes = result.stdout

                seen_pids = set()

                for line in processes.split('\n')[1:]:  # 跳过标题行
                    parts = line.split(None, 10)
                    if len(parts) < 11:
                        continue

                    user = parts[0]
                    pid = parts[1]
                    command = parts[10]
                    seen_pids.add(pid)

                    # 检查恶意进程特征
                    for pattern, desc in SUSPICIOUS_PROCESS_PATTERNS:
                        if re.search(pattern, command, re.IGNORECASE):
                            if pid not in seen_pids:
                                break

                            self.add_alert('CRITICAL', 'PROCESS',
                                '检测到恶意进程: {}'.format(desc),
                                'PID={} USER={} CMD={}'.format(pid, user, command[:100])
                            )
                            self.threats_blocked += 1
                            self.kill_process(pid, desc)
                            break

                    # 检查已知恶意文件路径
                    for bad_path in KNOWN_BAD_PROCESSES:
                        if bad_path in command:
                            self.add_alert('CRITICAL', 'PROCESS',
                                '检测到 Beacon 进程运行',
                                'PID={} CMD={}'.format(pid, command[:100])
                            )
                            self.threats_blocked += 1
                            self.kill_process(pid, 'Beacon 后门')
                            # 同时删除文件
                            if os.path.exists(bad_path):
                                try:
                                    os.remove(bad_path)
                                    self.add_action('DELETE', bad_path, '已删除恶意文件')
                                except Exception:
                                    pass
                            break

                    # 检查 apache 用户的异常子进程
                    if user == WEB_SERVER_USER and 'python' in command.lower():
                        if '/tmp/' in command or 'beacon' in command.lower():
                            self.add_alert('CRITICAL', 'PROCESS',
                                'Web 服务用户运行可疑 Python 进程',
                                'PID={} CMD={}'.format(pid, command[:100])
                            )
                            self.threats_blocked += 1
                            self.kill_process(pid, '可疑 Python 进程')

            except Exception as e:
                pass

            time.sleep(3)

    def kill_process(self, pid, reason):
        """终止进程"""
        try:
            subprocess.run(['kill', '-9', pid], capture_output=True, timeout=5)
            self.add_action('KILL', pid, '已终止: ' + reason)
            self.add_alert('INFO', 'PROCESS', '进程已终止', 'PID={} 原因={}'.format(pid, reason))
        except Exception as e:
            self.add_action('KILL', pid, '终止失败: ' + str(e))

    # ========== 控制接口 ==========

    def activate(self):
        """激活防护"""
        self.active = True
        self.add_alert('INFO', 'SYSTEM', '防御智能体已激活', '开始监控所有威胁')
        print("\033[92m[+] 防御智能体已激活 - 防护模式: ON\033[0m")

    def deactivate(self):
        """关闭防护"""
        self.active = False
        self.add_alert('WARNING', 'SYSTEM', '防御智能体已关闭', '防护已停止')
        print("\033[93m[!] 防御智能体已关闭 - 防护模式: OFF\033[0m")

    def toggle(self):
        """切换防护状态"""
        if self.active:
            self.deactivate()
        else:
            self.activate()
        return self.active

    def start(self):
        """启动防御智能体"""
        self.running = True

        # 启动监控线程
        t1 = threading.Thread(target=self.file_monitor_loop, daemon=True)
        t2 = threading.Thread(target=self.network_monitor_loop, daemon=True)
        t3 = threading.Thread(target=self.process_monitor_loop, daemon=True)

        self.threads = [t1, t2, t3]
        t1.start()
        t2.start()
        t3.start()

        self.add_alert('INFO', 'SYSTEM', '防御智能体启动', '监控线程已就绪')
        print("[*] 防御智能体已启动 (防护默认关闭)")

    def stop(self):
        """停止防御智能体"""
        self.running = False
        self.active = False
        self.add_alert('INFO', 'SYSTEM', '防御智能体停止', '')
        print("[*] 防御智能体已停止")

    def get_status(self):
        """获取当前状态"""
        with self.alerts_lock:
            alerts = list(self.alerts)
        with self.actions_lock:
            actions = list(self.actions)
        return {
            'running': self.running,
            'active': self.active,
            'scan_count': self.scan_count,
            'threats_blocked': self.threats_blocked,
            'alerts': alerts[-20:],
            'actions': actions[-20:],
            'alert_count': len(alerts),
            'action_count': len(actions),
        }

    def get_alerts(self):
        """获取告警列表"""
        with self.alerts_lock:
            return list(self.alerts)

    def get_actions(self):
        """获取处置记录"""
        with self.actions_lock:
            return list(self.actions)


# ========== 全局实例 ==========
agent = DefenseAgent()


def signal_handler(sig, frame):
    """信号处理"""
    agent.stop()
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    agent.start()

    # 保持运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
